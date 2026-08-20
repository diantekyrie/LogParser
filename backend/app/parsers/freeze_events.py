"""Parser for ActivityManager process freeze/unfreeze events -- the fifth
parser module named in the original build brief and initially dropped by
mistake. These aren't in a `dumpsys` section; they're logcat lines inside
the "SYSTEM LOG" captured-command section:

    08-13 22:36:22.190  1000  2046  2922 D ActivityManager: freezing 28798 com.android.vending:background
    08-13 22:36:13.874  1000  2046  3118 D ActivityManager: sync unfroze 7993 com.google.android.permissioncontroller for 6

The cached-process freezer pauses a backgrounded process's CPU/binder
activity; a process that's frozen when something expects it to respond
(or one thrashing freeze/unfreeze) is a real, otherwise-invisible root
cause for "app didn't do X" reports.
"""
from __future__ import annotations

import re

from app.parsers.base import ProcessFreezeEvent, SourceRef
from app.parsers.section_extractor import Section

FREEZE_RE = re.compile(
    r"^(?P<ts>\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+\d+\s+\d+\s+\d+ "
    r"D ActivityManager: freezing (?P<pid>\d+) (?P<proc>\S+)\s*$"
)

UNFREEZE_RE = re.compile(
    r"^(?P<ts>\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+\d+\s+\d+\s+\d+ "
    r"D ActivityManager: sync unfroze (?P<pid>\d+) (?P<proc>\S+) for (?P<dur>\d+)\s*$"
)


def parse_freeze_events(section: Section) -> list[ProcessFreezeEvent]:
    out: list[ProcessFreezeEvent] = []

    for i, raw in enumerate(section.lines):
        abs_line = section.line_start + i
        ref = SourceRef(section.name, abs_line, abs_line)

        m = FREEZE_RE.match(raw)
        if m:
            proc = m.group("proc")
            out.append(ProcessFreezeEvent(
                timestamp=m.group("ts"),
                event_type="freeze",
                pid=int(m.group("pid")),
                process=proc,
                package=proc.split(":")[0],
                unfreeze_reason_code=None,
                source_ref=ref,
            ))
            continue

        m = UNFREEZE_RE.match(raw)
        if m:
            proc = m.group("proc")
            out.append(ProcessFreezeEvent(
                timestamp=m.group("ts"),
                event_type="unfreeze",
                pid=int(m.group("pid")),
                process=proc,
                package=proc.split(":")[0],
                unfreeze_reason_code=int(m.group("dur")),
                source_ref=ref,
            ))

    return out
