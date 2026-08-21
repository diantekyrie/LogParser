"""Regression tests for the packet-analysis fallback backend
(app/parsers/packet_analysis.py).

Real .pcap test files used to build/verify this parser are two ~30-90MB
802.11 monitor-mode captures (not committed -- too big), used to:
  - Benchmark that generic scapy per-packet dissection is far too slow at
    real capture sizes (>120s for one RadioTap layer per packet on a
    297,262-packet file) -- this is WHY the fallback backend hand-parses
    radiotap/802.11 headers directly instead of using scapy for the hot
    path.
  - Verify the hand-rolled RSSI (dBm Antenna Signal) extraction exactly
    matches scapy's own RadioTap.dBm_AntSignal decoding (0 mismatches
    across 3000 real packets) before trusting it for a full-file run.
  - Confirm real signal is found: SSID "pixel_simhouse" (the same SSID the
    wifi.py parser separately found a disconnection event for in the
    matching bugreport), multiple BSSIDs, and 24 real deauthentication
    frames with source MAC addresses.

These tests use small synthetic pcap files built from scratch instead,
pinning down the exact byte-level parsing so a regression is caught without
needing the large real files.
"""
from __future__ import annotations

import struct

import pytest

from app.parsers.packet_analysis import (
    _analyze_dot11_fallback,
    _dot11_frame_control,
    _radiotap_rssi_and_header_len,
    analyze_packet_capture,
    dot11_frame_label,
)

PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"


def _pcap_global_header(linktype: int) -> bytes:
    return PCAP_MAGIC_LE + struct.pack("<HHiiii", 2, 4, 0, 0, 65535, linktype)


def _pcap_record(pkt: bytes, ts_sec: int = 0, ts_usec: int = 0) -> bytes:
    return struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt)) + pkt


def _radiotap_with_rssi(rssi_dbm: int) -> bytes:
    # present = bit5 only (dBm Antenna Signal). No fields before it, so the
    # RSSI byte sits immediately after the 8-byte radiotap header.
    present = 1 << 5
    header = struct.pack("<BBHI", 0, 0, 9, present)
    rssi_byte = bytes([rssi_dbm & 0xFF])  # two's complement for negative dBm
    return header + rssi_byte  # 9 bytes total


def _dot11_frame_control_bytes(ftype: int, subtype: int, retry: bool = False) -> bytes:
    byte0 = ((subtype & 0xF) << 4) | ((ftype & 0x3) << 2)
    byte1 = 0x08 if retry else 0x00
    return bytes([byte0, byte1])


def _dot11_mgmt_header(ftype: int, subtype: int, addr2: bytes, retry: bool = False) -> bytes:
    fc = _dot11_frame_control_bytes(ftype, subtype, retry)
    duration = b"\x00\x00"
    addr1 = b"\xff\xff\xff\xff\xff\xff"
    addr3 = b"\x11\x22\x33\x44\x55\x66"
    seqctl = b"\x00\x00"
    return fc + duration + addr1 + addr2 + addr3 + seqctl


def _beacon_with_ssid(addr2: bytes, ssid: str) -> bytes:
    header = _dot11_mgmt_header(0, 8, addr2)  # type=Management, subtype=Beacon
    fixed = b"\x00" * 8 + b"\x00\x00" + b"\x01\x04"  # Timestamp(8) + Interval(2) + CapInfo(2)
    ie = bytes([0, len(ssid)]) + ssid.encode("utf-8")  # tag 0 = SSID
    return header + fixed + ie


def test_radiotap_rssi_extraction_matches_expected_byte_offset():
    pkt = _radiotap_with_rssi(-71) + _dot11_frame_control_bytes(0, 12)
    rssi, rt_len = _radiotap_rssi_and_header_len(pkt)
    assert rssi == -71
    assert rt_len == 9


def test_dot11_frame_control_parses_type_subtype_and_retry():
    pkt = _radiotap_with_rssi(-50) + _dot11_frame_control_bytes(0, 12, retry=True)
    rssi, rt_len = _radiotap_rssi_and_header_len(pkt)
    parsed = _dot11_frame_control(pkt, rt_len)
    assert parsed == (0, 12, True)
    assert dot11_frame_label(0, 12) == "Deauthentication"


def test_fallback_backend_finds_deauth_beacon_ssid_and_rssi_range(tmp_path):
    deauth_pkt = _radiotap_with_rssi(-60) + _dot11_mgmt_header(
        0, 12, addr2=b"\xaa\xbb\xcc\xdd\xee\xff"
    )
    beacon_pkt = _radiotap_with_rssi(-40) + _beacon_with_ssid(
        addr2=b"\x11\x22\x33\x44\x55\x66", ssid="test_network"
    )
    retry_data_pkt = _radiotap_with_rssi(-80) + _dot11_frame_control_bytes(2, 0, retry=True)

    pcap_path = tmp_path / "synthetic.pcap"
    pcap_path.write_bytes(
        _pcap_global_header(127)  # Radiotap linktype
        + _pcap_record(deauth_pkt)
        + _pcap_record(beacon_pkt)
        + _pcap_record(retry_data_pkt)
    )

    result = _analyze_dot11_fallback(pcap_path)
    assert result.backend == "fallback"
    assert result.packets_analyzed == 3
    assert result.rssi_min_dbm == -80
    assert result.rssi_max_dbm == -40
    assert result.retry_count == 1

    labels = {f.label: f.count for f in result.frame_type_breakdown}
    assert labels["Deauthentication"] == 1
    assert labels["Beacon"] == 1
    assert labels["Data"] == 1

    ssids = {s.value for s in result.identity_signals if s.kind == "ssid"}
    assert "test_network" in ssids

    assert len(result.anomalies) == 1
    assert result.anomalies[0].kind == "deauthentication"
    assert result.anomalies[0].mac_or_ip == "aa:bb:cc:dd:ee:ff"


def test_analyze_packet_capture_uses_fallback_when_tshark_unavailable(tmp_path, monkeypatch):
    import app.parsers.packet_analysis as pa_module

    monkeypatch.setattr(pa_module, "tshark_available", lambda: False)

    pkt = _radiotap_with_rssi(-55) + _dot11_frame_control_bytes(0, 8)  # Beacon, no IEs
    pcap_path = tmp_path / "synthetic.pcap"
    pcap_path.write_bytes(_pcap_global_header(127) + _pcap_record(pkt))

    result = analyze_packet_capture(pcap_path, linktype=127)
    assert result is not None
    assert result.backend == "fallback"
    assert result.link_layer == "802.11"


def test_analyze_packet_capture_returns_none_for_unsupported_linktype(tmp_path):
    pcap_path = tmp_path / "synthetic.pcap"
    pcap_path.write_bytes(_pcap_global_header(0) + _pcap_record(b"\x00" * 20))
    result = analyze_packet_capture(pcap_path, linktype=0)  # linktype 0 = unsupported here
    assert result is None
