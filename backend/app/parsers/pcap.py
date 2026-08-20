"""Minimal classic PCAP parser for direct packet-capture uploads.

This does not try to decode Bluetooth/Wi-Fi protocols yet. It validates the
classic libpcap container, counts packets, reports byte totals, time bounds,
link type, and malformed/truncated record counts.
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

LINKTYPE_NAMES = {
    1: "Ethernet",
    105: "IEEE 802.11",
    127: "Radiotap",
    187: "Bluetooth HCI H4",
    201: "Bluetooth HCI H4 with direction",
    255: "Bluetooth LE LL",
}


def _timestamp(seconds: int, fraction: int, resolution: str) -> str:
    micros = fraction // 1000 if resolution == "nanoseconds" else fraction
    return datetime.fromtimestamp(seconds + micros / 1_000_000, timezone.utc).isoformat()


def parse_pcap(data: bytes) -> PacketCaptureSummary:
    if len(data) < 24:
        raise ValueError("PCAP file is too small to contain a global header")

    magic = data[:4]
    if magic not in MAGIC:
        raise ValueError("Unsupported packet capture format; expected classic .pcap")

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

        stamp = _timestamp(ts_sec, ts_frac, resolution)
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
