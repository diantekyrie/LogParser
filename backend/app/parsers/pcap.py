"""Minimal PCAP/PCAPNG parser for direct packet-capture uploads.

This does not try to decode Bluetooth/Wi-Fi protocols yet. It validates the
packet-capture container, counts packets, reports byte totals, time bounds,
link type, and malformed/truncated record counts. Both classic libpcap and
pcapng are supported because Wireshark commonly writes pcapng even when the
file is casually described as a "pcap."
"""
from __future__ import annotations

import struct
from datetime import datetime, timezone

from app.parsers.base import PacketCaptureSummary

MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", "microseconds"),
    b"\xa1\xb2\xc3\xd4": (">", "microseconds"),
    b"\x4d\x3c\xb2\xa1": ("<", "nanoseconds"),
    b"\xa1\xb2\x3c\x4d": (">", "nanoseconds"),
}
PCAPNG_SECTION_HEADER = b"\x0a\x0d\x0d\x0a"
PCAPNG_BYTE_ORDER = {
    b"\x4d\x3c\x2b\x1a": "<",
    b"\x1a\x2b\x3c\x4d": ">",
}
PCAPNG_IDB = 0x00000001
PCAPNG_EPB = 0x00000006
PCAPNG_IF_TSRESOL = 9

LINKTYPE_NAMES = {
    1: "Ethernet",
    105: "IEEE 802.11",
    127: "Radiotap",
    187: "Bluetooth HCI H4",
    201: "Bluetooth HCI H4 with direction",
    255: "Bluetooth LE LL",
}


def _classic_timestamp(seconds: int, fraction: int, resolution: str) -> str:
    micros = fraction // 1000 if resolution == "nanoseconds" else fraction
    return datetime.fromtimestamp(seconds + micros / 1_000_000, timezone.utc).isoformat()


def _pcapng_timestamp(raw_timestamp: int, denominator: int) -> str:
    return datetime.fromtimestamp(raw_timestamp / denominator, timezone.utc).isoformat()


def _padded(length: int) -> int:
    return (length + 3) & ~3


def _option_value(options: bytes, endian: str, wanted_code: int) -> bytes | None:
    offset = 0
    while offset + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[offset:offset + 4])
        offset += 4
        if code == 0:
            return None
        if offset + length > len(options):
            return None
        value = options[offset:offset + length]
        if code == wanted_code:
            return value
        offset += _padded(length)
    return None


def _tsresol_denominator(option: bytes | None) -> int:
    if not option:
        return 1_000_000
    value = option[0]
    if value & 0x80:
        return 2 ** (value & 0x7F)
    return 10 ** value


def parse_pcap(data: bytes) -> PacketCaptureSummary:
    if len(data) < 24:
        raise ValueError("PCAP file is too small to contain a global header")

    magic = data[:4]
    if magic == PCAPNG_SECTION_HEADER:
        return parse_pcapng(data)
    if magic not in MAGIC:
        raise ValueError("Unsupported packet capture format; expected classic .pcap or .pcapng")

    endian, resolution = MAGIC[magic]
    _major, _minor, _thiszone, _sigfigs, _snaplen, linktype = struct.unpack(
        endian + "HHiiii", data[4:24]
    )

    offset = 24
    total_packets = 0
    captured_bytes = 0
    original_bytes = 0
    truncated_packets = 0
    malformed_packets = 0
    first_timestamp = None
    last_timestamp = None

    while offset < len(data):
        if len(data) - offset < 16:
            malformed_packets += 1
            break

        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16

        if incl_len > len(data) - offset:
            malformed_packets += 1
            break

        stamp = _classic_timestamp(ts_sec, ts_frac, resolution)
        first_timestamp = first_timestamp or stamp
        last_timestamp = stamp
        total_packets += 1
        captured_bytes += incl_len
        original_bytes += orig_len
        if incl_len < orig_len:
            truncated_packets += 1

        offset += incl_len

    return PacketCaptureSummary(
        format="pcap",
        linktype=linktype,
        linktype_name=LINKTYPE_NAMES.get(linktype, f"LinkType {linktype}"),
        total_packets=total_packets,
        captured_bytes=captured_bytes,
        original_bytes=original_bytes,
        first_timestamp=first_timestamp,
        last_timestamp=last_timestamp,
        truncated_packets=truncated_packets,
        malformed_packets=malformed_packets,
    )


def parse_pcapng(data: bytes) -> PacketCaptureSummary:
    if len(data) < 28:
        raise ValueError("PCAPNG file is too small to contain a section header")
    if data[:4] != PCAPNG_SECTION_HEADER:
        raise ValueError("Unsupported packet capture format; expected .pcapng section header")

    endian = PCAPNG_BYTE_ORDER.get(data[8:12])
    if endian is None:
        raise ValueError("Unsupported pcapng byte order")

    offset = 0
    interfaces: list[dict] = []
    total_packets = 0
    captured_bytes = 0
    original_bytes = 0
    truncated_packets = 0
    malformed_packets = 0
    first_timestamp = None
    last_timestamp = None

    while offset < len(data):
        if len(data) - offset < 12:
            malformed_packets += 1
            break

        block_type, block_len = struct.unpack(endian + "II", data[offset:offset + 8])
        if block_len < 12 or offset + block_len > len(data):
            malformed_packets += 1
            break

        body = data[offset + 8:offset + block_len - 4]
        trailing_len = struct.unpack(endian + "I", data[offset + block_len - 4:offset + block_len])[0]
        if trailing_len != block_len:
            malformed_packets += 1
            break

        if block_type == int.from_bytes(PCAPNG_SECTION_HEADER, "big"):
            next_endian = PCAPNG_BYTE_ORDER.get(body[:4])
            if next_endian is not None:
                endian = next_endian
        elif block_type == PCAPNG_IDB:
            if len(body) < 8:
                malformed_packets += 1
                break
            linktype, _reserved, snaplen = struct.unpack(endian + "HHI", body[:8])
            tsresol = _tsresol_denominator(_option_value(body[8:], endian, PCAPNG_IF_TSRESOL))
            interfaces.append({"linktype": linktype, "snaplen": snaplen, "tsresol": tsresol})
        elif block_type == PCAPNG_EPB:
            if len(body) < 20:
                malformed_packets += 1
                break
            interface_id, ts_high, ts_low, incl_len, orig_len = struct.unpack(endian + "IIIII", body[:20])
            packet_end = 20 + _padded(incl_len)
            if packet_end > len(body):
                malformed_packets += 1
                break
            interface = interfaces[interface_id] if interface_id < len(interfaces) else {"tsresol": 1_000_000}
            raw_timestamp = (ts_high << 32) | ts_low
            stamp = _pcapng_timestamp(raw_timestamp, interface["tsresol"])
            first_timestamp = first_timestamp or stamp
            last_timestamp = stamp
            total_packets += 1
            captured_bytes += incl_len
            original_bytes += orig_len
            if incl_len < orig_len:
                truncated_packets += 1

        offset += block_len

    linktype = interfaces[0]["linktype"] if interfaces else -1
    return PacketCaptureSummary(
        format="pcapng",
        linktype=linktype,
        linktype_name=LINKTYPE_NAMES.get(linktype, f"LinkType {linktype}"),
        total_packets=total_packets,
        captured_bytes=captured_bytes,
        original_bytes=original_bytes,
        first_timestamp=first_timestamp,
        last_timestamp=last_timestamp,
        truncated_packets=truncated_packets,
        malformed_packets=malformed_packets,
    )
