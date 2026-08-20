"""Parser for Java `FATAL EXCEPTION` crashes in the system log.

    08-13 22:39:04.221 1010247  6962  6998 E AndroidRuntime: FATAL EXCEPTION: SystemUIBg-7
    08-13 22:39:04.221 1010247  6962  6998 E AndroidRuntime: Process: com.android.systemui, PID: 6962
    08-13 22:39:04.221 1010247  6962  6998 E AndroidRuntime: DeadSystemException: The system died; earlier logs will point to the root cause

Three consecutive AndroidRuntime lines carry the crash header, the
offending process, and the exception class/message. Native crashes
(tombstones) are not text in this section at all -- see
ingestion.list_native_crash_files, which reads them straight from the zip's
file listing.
"""
from __future__ import annotations

import re

from app.parsers.base import CrashEvent, SourceRef
from app.parsers.section_extractor import Section

LOG_LINE_RE = re.compile(
    r"^(?P<ts>\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+\d+\s+\d+\s+\d+ E AndroidRuntime: (?P<rest>.*)$"
)
FATAL_RE = re.compile(r"^FATAL EXCEPTION: (?P<thread>.+)$")
PROCESS_RE = re.compile(r"^Process: (?P<pkg>[\w.\-:]+), PID: (?P<pid>\d+)$")
EXCEPTION_RE = re.compile(r"^([\w.$]*Exception[\w.$]*|Error): ?(.*)$")


def parse_crash_events(section: Section) -> list[CrashEvent]:
    out: list[CrashEvent] = []
    n = len(section.lines)
    i = 0
    while i < n:
        m = LOG_LINE_RE.match(section.lines[i])
        if not m or not FATAL_RE.match(m.group("rest")):
            i += 1
            continue

        thread = FATAL_RE.match(m.group("rest")).group("thread")
        ts = m.group("ts")
        start_line = section.line_start + i

        package = pid = exception_class = message = None
        end_line = start_line

        # The next couple of AndroidRuntime lines (same timestamp block)
        # carry Process:/exception details.
        j = i + 1
        lookahead_limit = min(n, i + 6)
        while j < lookahead_limit:
            m2 = LOG_LINE_RE.match(section.lines[j])
            if not m2:
                break
            rest = m2.group("rest")
            pm = PROCESS_RE.match(rest)
            if pm:
                package = pm.group("pkg")
                pid = int(pm.group("pid"))
                end_line = section.line_start + j
                j += 1
                continue
            em = EXCEPTION_RE.match(rest)
            if em and exception_class is None:
                exception_class = em.group(1)
                message = em.group(2)
                end_line = section.line_start + j
                break
            j += 1

        out.append(CrashEvent(
            timestamp=ts, thread=thread, package=package, pid=pid,
            exception_class=exception_class, message=message,
            source_ref=SourceRef("system_log", start_line, end_line),
        ))
        i += 1

    return out
