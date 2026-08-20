import struct

from sqlmodel import Session, SQLModel, create_engine, select

from app.models.db_models import Capture, Investigation, InvestigationCaptureLink, PacketCaptureSummaryRow
from app.parsers.pcap import parse_pcap
from app.parsers.base import ParsedCapture
from app.services.persistence import persist_capture
from app.services.summary import build_capture_summary


def _classic_pcap() -> bytes:
    header = b"\xd4\xc3\xb2\xa1" + struct.pack(
        "<HHiiii",
        2,      # major
        4,      # minor
        0,      # thiszone
        0,      # sigfigs
        65535,  # snaplen
        1,      # Ethernet
    )
    pkt1 = struct.pack("<IIII", 1_800_000_000, 123456, 4, 4) + b"abcd"
    pkt2 = struct.pack("<IIII", 1_800_000_001, 0, 2, 4) + b"ef"
    return header + pkt1 + pkt2


def _block(endian: str, block_type: int, body: bytes) -> bytes:
    total_len = 12 + len(body)
    return struct.pack(endian + "II", block_type, total_len) + body + struct.pack(endian + "I", total_len)


def _pcapng() -> bytes:
    endian = "<"
    section = _block(
        endian,
        0x0A0D0D0A,
        b"\x4d\x3c\x2b\x1a" + struct.pack(endian + "HHq", 1, 0, -1),
    )
    interface = _block(
        endian,
        0x00000001,
        struct.pack(endian + "HHI", 1, 0, 65535),
    )
    packet_data = b"abcd"
    timestamp = 1_800_000_000_000_000
    packet = _block(
        endian,
        0x00000006,
        struct.pack(
            endian + "IIIII",
            0,
            timestamp >> 32,
            timestamp & 0xFFFFFFFF,
            len(packet_data),
            len(packet_data),
        )
        + packet_data,
    )
    return section + interface + packet


def test_parse_classic_pcap_summary():
    summary = parse_pcap(_classic_pcap())

    assert summary.format == "pcap"
    assert summary.linktype_name == "Ethernet"
    assert summary.total_packets == 2
    assert summary.captured_bytes == 6
    assert summary.original_bytes == 8
    assert summary.truncated_packets == 1
    assert summary.malformed_packets == 0
    assert summary.first_timestamp is not None
    assert summary.last_timestamp is not None


def test_parse_pcapng_summary():
    summary = parse_pcap(_pcapng())

    assert summary.format == "pcapng"
    assert summary.linktype_name == "Ethernet"
    assert summary.total_packets == 1
    assert summary.captured_bytes == 4
    assert summary.original_bytes == 4
    assert summary.truncated_packets == 0
    assert summary.malformed_packets == 0
    assert summary.first_timestamp is not None


def test_investigation_groups_multiple_captures():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)

    with Session(engine) as session:
        first = ParsedCapture()
        first.packet_capture_summary = parse_pcap(_classic_pcap())
        cap1 = persist_capture(session, "local-device", "trace.pcap", first, investigation_label="hotel-wifi-drop")
        cap2 = persist_capture(session, "local-device", "bugreport.txt", ParsedCapture(), investigation_label="hotel-wifi-drop")

        investigation = session.exec(
            select(Investigation).where(Investigation.label == "hotel-wifi-drop")
        ).one()
        links = session.exec(
            select(InvestigationCaptureLink).where(
                InvestigationCaptureLink.investigation_id == investigation.id
            )
        ).all()

        assert {link.capture_id for link in links} == {cap1.id, cap2.id}
        assert session.exec(select(Capture)).all()
        assert session.exec(select(PacketCaptureSummaryRow)).one().total_packets == 2
        assert build_capture_summary(session, cap1.id)["packet_capture_summary"]["total_packets"] == 2
