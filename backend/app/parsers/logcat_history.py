"""Parses the persistent, rotated logcat ring-buffer files kept on-device
under FS/data/misc/logd/ inside the bugreport zip (logcat.01, logcat.02,
..., logcat.NN) -- these hold log history that predates the live logcat
capture in the flattened bugreport's "SYSTEM LOG" section, sometimes going
back days rather than the hours a live capture typically covers.

Real gap found live: neither real test bugreport's rotated logcat history
was being read at all (63 files on one device, 26 on the other); every
diagnosis this whole session only ever saw whatever fell inside the live
buffer window captured in "SYSTEM LOG".

Rather than duplicating regex logic, this reuses the exact same event
parsers already built for system_log (process freezes, Java crashes,
CDM/Fast Pair pairing events) by wrapping each rotated file's lines as a
synthetic Section, tagged with a distinct per-file section name (e.g.
"logcat.01") so every citation still points at the specific file the fact
came from -- never mislabeled as "system_log".

Timestamp format difference: these files use 6-digit microsecond precision
("06-25 10:15:31.895901"), not the 3-digit millisecond precision
("10:15:31.895") the existing parsers' regexes expect -- lines are
normalized to 3-digit millisecond precision before being handed to the
existing parsers so no regex needs duplicating or loosening.

The bare "logcat" file (no numeric suffix -- the currently-active buffer at
capture time) is deliberately skipped: it substantially overlaps the
already-parsed "SYSTEM LOG" section content, so including it would mostly
duplicate facts already in the bundle rather than add new history.
"""
from __future__ import annotations

import re
import zipfile

from app.parsers.base import CdmPairingEvent, CrashEvent, ProcessFreezeEvent
from app.parsers.cdm_pairing import parse_cdm_pairing_events
from app.parsers.crash_events import parse_crash_events
from app.parsers.freeze_events import parse_freeze_events
from app.parsers.section_extractor import Section

LOGCAT_HISTORY_DIR = "FS/data/misc/logd/"
LOGCAT_HISTORY_NAME_RE = re.compile(r"^logcat\.(\d+)$")

# "06-25 10:15:31.895901 ..." -> "06-25 10:15:31.895 ..." (keep the first 3
# of the 6 fractional-second digits, drop the rest).
MICROSECOND_TS_RE = re.compile(r"^(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\d{3}\b")


def _normalize_timestamp_precision(line: str) -> str:
    return MICROSECOND_TS_RE.sub(r"\1", line, count=1)


def _iter_history_files(zf: zipfile.ZipFile):
    for info in zf.infolist():
        name = info.filename
        if not name.startswith(LOGCAT_HISTORY_DIR):
            continue
        base = name[len(LOGCAT_HISTORY_DIR):]
        if "/" in base:
            continue
        m = LOGCAT_HISTORY_NAME_RE.match(base)
        if m:
            yield name, m.group(1)


def parse_logcat_history(
    zf: zipfile.ZipFile,
) -> tuple[list[ProcessFreezeEvent], list[CrashEvent], list[CdmPairingEvent]]:
    freeze_events: list[ProcessFreezeEvent] = []
    crash_events: list[CrashEvent] = []
    cdm_events: list[CdmPairingEvent] = []

    for name, suffix in _iter_history_files(zf):
        text = zf.read(name).decode("utf-8", errors="replace")
        lines = [_normalize_timestamp_precision(line) for line in text.split("\n")]
        section = Section(
            name=f"logcat.{suffix}", priority=None,
            line_start=1, line_end=len(lines), lines=lines, kind="log",
        )

        freeze_events.extend(parse_freeze_events(section))
        crash_events.extend(parse_crash_events(section))
        cdm_events.extend(parse_cdm_pairing_events(section))

    return freeze_events, crash_events, cdm_events
