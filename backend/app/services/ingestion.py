"""Orchestrates turning an uploaded bugreport zip into a ParsedCapture of
structured facts. This is the only place raw bugreport text gets touched;
everything downstream (verification, correlation, LLM reasoning) works off
ParsedCapture / persisted rows, never re-parses raw text.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

from app.parsers import WANTED_SECTIONS, ParsedCapture
from app.parsers.audio_focus import parse_audio_focus
from app.parsers.foreground_service import parse_foreground_services
from app.parsers.media_session import parse_media_sessions
from app.parsers.package_info import parse_packages
from app.parsers.section_extractor import extract_sections


def parse_bugreport_zip(zip_path: str | Path) -> ParsedCapture:
    capture = ParsedCapture()

    with zipfile.ZipFile(zip_path) as zf:
        sections = extract_sections(zf, WANTED_SECTIONS)

    if "audio" in sections:
        capture.focus_stack, capture.focus_events = parse_audio_focus(sections["audio"])
    else:
        capture.parse_warnings.append("No 'audio' dumpsys section found")

    if "package" in sections:
        capture.packages = parse_packages(sections["package"])
    else:
        capture.parse_warnings.append("No 'package' dumpsys section found")

    if "media_session" in sections:
        capture.media_sessions = parse_media_sessions(sections["media_session"])
    else:
        capture.parse_warnings.append("No 'media_session' dumpsys section found")

    if "activity" in sections:
        capture.foreground_services = parse_foreground_services(sections["activity"])
    else:
        capture.parse_warnings.append("No 'activity' dumpsys section found")

    return capture
