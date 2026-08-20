"""Parser for the `DUMP OF SERVICE audio` -> `## MediaFocusControl` subsection.

This is the section logcat.ai's retrieval reported as "missing" across 8
search attempts on a real bugreport, when a plain `grep` found it instantly.
It is dense, low-natural-language-signal, line-oriented data -- exactly the
kind of section chunk/embedding retrieval silently drops. We parse it
deterministically instead.

Two things live here:
  1. "Audio Focus stack entries" -- a snapshot of who currently holds focus.
  2. "focus commands as seen by MediaFocusControl" -- the full timestamped
     history of request/abandon/owner-change events for this capture.
"""
from __future__ import annotations

import re

from app.parsers.base import FocusEvent, FocusStackEntry, SourceRef
from app.parsers.section_extractor import Section

STACK_HEADER = "Audio Focus stack entries (last is top of stack):"
EVENTS_HEADER = "focus commands as seen by MediaFocusControl"

STACK_ENTRY_RE = re.compile(
    r"^\s*source:(?P<source>\S+)"
    r" -- pack: (?P<pack>\S+)"
    r" -- client: (?P<client>\S+)"
    r" -- gain: (?P<gain>\S+)"
    r" -- flags:\s*(?P<flags>\S*)"
    r" -- loss: (?P<loss>\S+)"
    r" -- notified: (?P<notified>\S+)"
    r" -- limbo(?P<limbo>\S+)"
    r" -- uid: (?P<uid>\d+)"
    r" -- attr: (?P<attr>.*?)"
    r" -- sdk:(?P<sdk>\d+)\s*$"
)

# 08-13 22:36:25:419 requestAudioFocus() from uid/pid 1010225/29225 AA=USAGE_.../CONTENT_TYPE_...
#   clientId=... callingPack=... req=1 flags=0x0 sdk=37
REQUEST_RE = re.compile(
    r"^(?P<ts>\d{2}-\d{2} \d{2}:\d{2}:\d{2}:\d{3}) requestAudioFocus\(\) from uid/pid "
    r"(?P<uid>\d+)/(?P<pid>\d+)(?: AA=(?P<aa>\S+))? clientId=(?P<client>\S+) "
    r"callingPack=(?P<pack>\S+)(?: req=(?P<req>\d+) flags=(?P<flags>\S+) sdk=(?P<sdk>\d+))?"
)

ABANDON_RE = re.compile(
    r"^(?P<ts>\d{2}-\d{2} \d{2}:\d{2}:\d{2}:\d{3}) abandonAudioFocus\(\) from uid/pid "
    r"(?P<uid>\d+)/(?P<pid>\d+) clientId=(?P<client>\S+) callingPack=(?P<pack>\S+)"
)

OWNER_RE = re.compile(
    r"^(?P<ts>\d{2}-\d{2} \d{2}:\d{2}:\d{2}:\d{3}) focus owner: (?P<client>\S+) "
    r"in uid: (?P<uid>\d+) pack: (?P<pack>\S+)(?: code: (?P<code>-?\d+))? "
    r"event:\s*(?P<detail>.*)$"
)


def _to_bool(token: str) -> bool | None:
    t = token.strip().lower()
    if t in ("true", "yes"):
        return True
    if t in ("false", "no"):
        return False
    return None


def parse_audio_focus(section: Section) -> tuple[list[FocusStackEntry], list[FocusEvent]]:
    stack: list[FocusStackEntry] = []
    events: list[FocusEvent] = []

    lines = section.lines
    n = len(lines)

    # --- Focus stack snapshot ---
    try:
        stack_idx = next(i for i, l in enumerate(lines) if l.strip() == STACK_HEADER)
    except StopIteration:
        stack_idx = None

    if stack_idx is not None:
        stack_lines: list[tuple[int, str]] = []
        i = stack_idx + 1
        while i < n and lines[i].strip():
            stack_lines.append((i, lines[i]))
            i += 1
        for idx, (offset, raw) in enumerate(stack_lines):
            m = STACK_ENTRY_RE.match(raw)
            if not m:
                continue
            abs_line = section.line_start + offset
            stack.append(FocusStackEntry(
                package=m.group("pack"),
                uid=int(m.group("uid")),
                client_id=m.group("client"),
                gain=m.group("gain"),
                flags=m.group("flags"),
                loss=m.group("loss"),
                notified=_to_bool(m.group("notified")),
                limbo=_to_bool(m.group("limbo")),
                sdk=int(m.group("sdk")) if m.group("sdk") else None,
                attrs=m.group("attr"),
                is_top_of_stack=(idx == len(stack_lines) - 1),
                source_ref=SourceRef("audio", abs_line, abs_line),
            ))

    # --- Focus event history ---
    try:
        events_idx = next(i for i, l in enumerate(lines) if EVENTS_HEADER in l)
    except StopIteration:
        events_idx = None

    if events_idx is not None:
        i = events_idx + 1
        while i < n:
            raw = lines[i]
            stripped = raw.strip()
            if not stripped:
                i += 1
                continue
            abs_line = section.line_start + i
            ref = SourceRef("audio", abs_line, abs_line)

            m = REQUEST_RE.match(stripped)
            if m:
                events.append(FocusEvent(
                    timestamp=m.group("ts"),
                    event_type="request",
                    package=m.group("pack"),
                    uid=int(m.group("uid")),
                    pid=int(m.group("pid")),
                    usage=m.group("aa"),
                    request_result=m.group("req"),
                    loss_code=None,
                    detail=stripped,
                    source_ref=ref,
                ))
                i += 1
                continue

            m = ABANDON_RE.match(stripped)
            if m:
                events.append(FocusEvent(
                    timestamp=m.group("ts"),
                    event_type="abandon",
                    package=m.group("pack"),
                    uid=int(m.group("uid")),
                    pid=int(m.group("pid")),
                    usage=None,
                    request_result=None,
                    loss_code=None,
                    detail=stripped,
                    source_ref=ref,
                ))
                i += 1
                continue

            m = OWNER_RE.match(stripped)
            if m:
                events.append(FocusEvent(
                    timestamp=m.group("ts"),
                    event_type="owner_change",
                    package=m.group("pack"),
                    uid=int(m.group("uid")),
                    pid=None,
                    usage=None,
                    request_result=None,
                    loss_code=m.group("code"),
                    detail=m.group("detail"),
                    source_ref=ref,
                ))
                i += 1
                continue

            # A non-matching, non-blank line ends the event-history block
            # (next subsection header, e.g. "Multi Audio Focus enabled").
            if not re.match(r"^\d{2}-\d{2} \d{2}:\d{2}:\d{2}:\d{3} ", stripped):
                break
            i += 1

    return stack, events
