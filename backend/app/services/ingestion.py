"""Orchestrates turning an uploaded bugreport zip into a ParsedCapture of
structured facts. This is the only place raw bugreport text gets touched;
everything downstream (verification, correlation, LLM reasoning) works off
ParsedCapture / persisted rows, never re-parses raw text.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

from app.parsers import WANTED_SECTIONS, ParsedCapture
from app.parsers.anr import parse_anr
from app.parsers.audio_focus import parse_audio_focus
from app.parsers.battery_stats import parse_battery_uid_stats
from app.parsers.bt_hci import parse_bt_hci_log
from app.parsers.cdm_pairing import parse_cdm_pairing_events
from app.parsers.crash_events import parse_crash_events
from app.parsers.device_info import parse_device_info
from app.parsers.foreground_service import parse_foreground_services
from app.parsers.freeze_events import parse_freeze_events
from app.parsers.media_session import parse_media_sessions
from app.parsers.package_info import parse_packages
from app.parsers.pcap import parse_pcap
from app.parsers.section_extractor import extract_sections, extract_sections_from_text
from app.parsers.tombstone import parse_tombstone
from app.parsers.wifi import parse_wifi_events

TOMBSTONE_PREFIX = "FS/data/tombstones/"
ANR_PREFIX = "FS/data/anr/"
BT_HCI_LOG_PATH = "FS/data/misc/bluetooth/logs/btsnooz_hci.log"


def _zip_entry_modified_at(info: zipfile.ZipInfo) -> str:
    return (f"{info.date_time[0]:04d}-{info.date_time[1]:02d}-{info.date_time[2]:02d} "
            f"{info.date_time[3]:02d}:{info.date_time[4]:02d}:{info.date_time[5]:02d}")


def parse_tombstones(zf: zipfile.ZipFile) -> list:
    out = []
    for info in zf.infolist():
        name = info.filename
        if not name.startswith(TOMBSTONE_PREFIX) or name.endswith(".pb"):
            continue
        base = name[len(TOMBSTONE_PREFIX):]
        if "/" in base or not base.startswith("tombstone_"):
            continue
        text = zf.read(name).decode("utf-8", errors="replace")
        out.append(parse_tombstone(base, _zip_entry_modified_at(info), text))
    out.sort(key=lambda t: t.modified_at)
    return out


def parse_anrs(zf: zipfile.ZipFile) -> list:
    out = []
    for info in zf.infolist():
        name = info.filename
        if not name.startswith(ANR_PREFIX):
            continue
        base = name[len(ANR_PREFIX):]
        if "/" in base or not base.startswith("anr_"):
            continue
        text = zf.read(name).decode("utf-8", errors="replace")
        out.append(parse_anr(base, text))
    out.sort(key=lambda a: a.filename)
    return out


def _parse_sections_into_capture(capture: ParsedCapture, sections: dict) -> ParsedCapture:
    """Run every section parser over already-extracted bugreport sections."""
    if "audio" in sections:
        capture.focus_stack, capture.focus_events = parse_audio_focus(sections["audio"])
    else:
        capture.parse_warnings.append("No 'audio' dumpsys section found")

    if "package" in sections:
        capture.packages = parse_packages(sections["package"])
    else:
        capture.parse_warnings.append("No 'package' dumpsys section found")

    if "batterystats" in sections:
        capture.battery_uid_stats = parse_battery_uid_stats(sections["batterystats"])
        # Attribute each UID to a package by matching uid % 100000 against
        # a known package's appId (appId is user-independent; the modulus
        # strips the userId*100000 term regardless of which user the UID
        # belongs to). Real gap found on the first real-data run: several
        # system appIds (1000, 1001, ...) are shared by a dozen-plus
        # packages via android:sharedUserId ("com.android.location.fused"
        # is one of 18 packages sharing appId 1000, the "system" UID) --
        # attributing that battery entry to whichever one happened to be
        # first in the dict would misrepresent a shared system UID's
        # activity as one specific app's. Only attribute when the appId is
        # unique to exactly one installed package; leave it unattributed
        # (not guessed) otherwise, same principle as tombstone/native-crash
        # attribution.
        app_id_owners: dict[int, list[str]] = {}
        for p in capture.packages.values():
            if p.app_id is not None:
                app_id_owners.setdefault(p.app_id, []).append(p.package)
        for stat in capture.battery_uid_stats:
            owners = app_id_owners.get(stat.uid % 100000, [])
            stat.package = owners[0] if len(owners) == 1 else None
    else:
        capture.parse_warnings.append("No 'batterystats' dumpsys section found")

    if "media_session" in sections:
        capture.media_sessions = parse_media_sessions(sections["media_session"])
    else:
        capture.parse_warnings.append("No 'media_session' dumpsys section found")

    if "activity" in sections:
        capture.foreground_services = parse_foreground_services(sections["activity"])
    else:
        capture.parse_warnings.append("No 'activity' dumpsys section found")

    if "system_log" in sections:
        capture.freeze_events = parse_freeze_events(sections["system_log"])
        capture.crash_events = parse_crash_events(sections["system_log"])
        capture.cdm_pairing_events = parse_cdm_pairing_events(sections["system_log"])
    else:
        capture.parse_warnings.append("No 'SYSTEM LOG' section found")

    if "wifi" in sections:
        capture.wifi_events = parse_wifi_events(sections["wifi"])
    else:
        capture.parse_warnings.append("No 'wifi' dumpsys section found")

    capture.device_info = parse_device_info(
        sections.get("preamble"), sections.get("system_properties")
    )
    if "preamble" not in sections:
        capture.parse_warnings.append("No preamble header block found")
    if "system_properties" not in sections:
        capture.parse_warnings.append("No 'SYSTEM PROPERTIES' section found")

    return capture


def parse_bugreport_zip(zip_path: str | Path) -> ParsedCapture:
    capture = ParsedCapture()

    with zipfile.ZipFile(zip_path) as zf:
        sections = extract_sections(zf, WANTED_SECTIONS)
        capture.tombstones = parse_tombstones(zf)
        capture.anrs = parse_anrs(zf)

        names = set(zf.namelist())
        if BT_HCI_LOG_PATH in names:
            capture.bt_hci_summary = parse_bt_hci_log(zf.read(BT_HCI_LOG_PATH))
        else:
            capture.parse_warnings.append("No Bluetooth HCI snoop log found")

    return _parse_sections_into_capture(capture, sections)


def parse_bugreport_txt(txt_path: str | Path) -> ParsedCapture:
    with Path(txt_path).open("r", encoding="utf-8", errors="replace", newline="\n") as f:
        text = f.read()
    capture = ParsedCapture()
    sections = extract_sections_from_text(text, WANTED_SECTIONS)
    capture.parse_warnings.append("Raw .txt upload: ZIP-only tombstone, ANR, and Bluetooth HCI files are not available")
    return _parse_sections_into_capture(capture, sections)


def parse_pcap_file(path: str | Path) -> ParsedCapture:
    capture = ParsedCapture()
    capture.packet_capture_summary = parse_pcap(Path(path).read_bytes())
    return capture


def parse_btt_file(path: str | Path) -> ParsedCapture:
    data = Path(path).read_bytes()
    capture = ParsedCapture()
    if data.startswith(b"btsnoop\0"):
        capture.bt_hci_summary = parse_bt_hci_log(data)
        capture.parse_warnings.append("Parsed .btt as btsnoop/HCI bytes")
    else:
        capture.parse_warnings.append(
            "Ellisys .btt upload accepted, but native .btt decoding is not implemented yet; "
            "export btsnoop/pcap from Ellisys or provide a sample/spec to add full decoding"
        )
    return capture


def parse_capture_file(path: str | Path, filename: str | None = None) -> ParsedCapture:
    suffix = Path(filename or path).suffix.lower()
    if suffix == ".zip":
        return parse_bugreport_zip(path)
    if suffix == ".txt":
        return parse_bugreport_txt(path)
    if suffix in {".pcap", ".pcapng"}:
        return parse_pcap_file(path)
    if suffix == ".btt":
        return parse_btt_file(path)
    raise ValueError("Unsupported upload type; expected .zip, .txt, .pcap, .pcapng, or .btt")
