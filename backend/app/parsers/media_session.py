"""Parser for `DUMP OF SERVICE media_session` -> the live MediaSession stack.

This is what lets us independently verify an "accused" app's own state
instead of taking a user's framing ("app X didn't pause") as fact: for every
session we get package, active flag, and parsed PlaybackState (state name,
state code, position, and the elapsedRealtime of the last update).
"""
from __future__ import annotations

import re

from app.parsers.base import MediaSessionFacts, SourceRef
from app.parsers.section_extractor import Section

MEDIA_BUTTON_SESSION_RE = re.compile(r"^Media button session is (?P<pkg>[\w.\-]+)/")

# "    Disney+ Media Session com.disney.disneyplus/Disney+ Media Session/201 (userId=0)"
SESSION_TAG_RE = re.compile(
    r"^\s{4}(?P<tag>.+?) (?P<pkg>[\w.\-]+)/(?:.+?)/(?P<idx>\d+) \(userId=(?P<user>\d+)\)\s*$"
)

ACTIVE_RE = re.compile(r"^\s*active=(?P<val>true|false)\s*$")

# state=PlaybackState {state=PLAYING(3), position=112861, buffered position=0, speed=1.0, updated=1919451677, ...}
PLAYBACK_STATE_RE = re.compile(
    r"^\s*state=PlaybackState \{state=(?P<name>\w+)\((?P<code>-?\d+)\), "
    r"position=(?P<pos>-?\d+), .*?updated=(?P<updated>\d+),"
)

PACKAGE_LINE_RE = re.compile(r"^\s*package=(?P<pkg>[\w.\-]+)\s*$")


def parse_media_sessions(section: Section) -> list[MediaSessionFacts]:
    lines = section.lines
    n = len(lines)

    media_button_pkg: str | None = None
    for l in lines:
        m = MEDIA_BUTTON_SESSION_RE.match(l.strip())
        if m:
            media_button_pkg = m.group("pkg")
            break

    out: list[MediaSessionFacts] = []
    i = 0
    while i < n:
        m = SESSION_TAG_RE.match(lines[i])
        if not m:
            i += 1
            continue

        tag = m.group("tag").strip()
        header_pkg = m.group("pkg")
        header_abs_line = section.line_start + i

        active = False
        state_name = None
        state_code = None
        position = None
        updated = None
        pkg = header_pkg
        last_abs_line = header_abs_line

        j = i + 1
        # A session block is indented 6 spaces; it ends at the next 4-space
        # indented tag line, or a dedent back to top level.
        while j < n and not SESSION_TAG_RE.match(lines[j]) and (lines[j].startswith(" ") or not lines[j].strip()):
            raw = lines[j]
            pm = PACKAGE_LINE_RE.match(raw)
            if pm:
                pkg = pm.group("pkg")
                last_abs_line = section.line_start + j
            am = ACTIVE_RE.match(raw)
            if am:
                active = am.group("val") == "true"
                last_abs_line = section.line_start + j
            sm = PLAYBACK_STATE_RE.match(raw)
            if sm:
                state_name = sm.group("name")
                state_code = int(sm.group("code"))
                position = int(sm.group("pos"))
                updated = int(sm.group("updated"))
                last_abs_line = section.line_start + j
            j += 1

        out.append(MediaSessionFacts(
            package=pkg,
            session_tag=tag,
            active=active,
            playback_state=state_name,
            playback_state_code=state_code,
            position_ms=position,
            updated_at_elapsed_ms=updated,
            is_media_button_session=(pkg == media_button_pkg),
            source_ref=SourceRef("media_session", header_abs_line, last_abs_line),
        ))
        i = j

    return out
