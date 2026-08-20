"""Parser for `DUMP OF SERVICE batterystats` -> "Estimated power use (mAh):"
-- per-UID battery attribution:

    UID u0a358: 99.0 fg: 12.2 (18m 26s 480ms) bg: 1.86 (1s 898ms) fgs: 31.4 (56m 54s 449ms) cached: 43.3 (37m 28s 999ms)
        screen=10.4 cpu=7.05 cpu:fg=3.91 cpu:bg=0.779 cpu:fgs=1.96 cpu:cached=0.402 audio=28.8 (1h 9m 9s 579ms) ...
    UID 1000: 31.5 bg: 31.5
        cpu=20.4 cpu:bg=20.4 camera=10.5 (9s 801ms) camera:bg=10.5 (9s 801ms) mobile_radio=0.171 ...

Two UID token shapes appear: a raw system UID ("1000", "0", "2000") or an
app UID ("u0a358", "u10a228" -- userId + appId-offset-from-10000). Package
attribution from the UID happens downstream (app/services/ingestion.py),
by matching `uid % 100000` against a known package's `appId` -- this
parser only produces the numeric uid, not the package.
"""
from __future__ import annotations

import re

from app.parsers.base import BatteryUidStats, SourceRef
from app.parsers.section_extractor import Section

POWER_USE_HEADER = "Estimated power use (mAh):"

UID_HEADER_RE = re.compile(r"^\s*UID (?P<token>\S+): (?P<total>[\d.]+)")
STATE_FIELD_RE = re.compile(r"\b(fg|bg|fgs|cached): ([\d.]+)")

# Top-level component fields only (e.g. "cpu=7.05"), not the ":subtype"
# breakdowns (e.g. "cpu:fg=3.91") -- the negative lookbehind stops a match
# starting mid-way through "cpu:fg=" from being misread as a top-level
# field named "fg".
COMPONENT_RE = re.compile(r"(?<![:\w])(?P<comp>[a-z_]+)=(?P<val>[\d.]+)")

APP_UID_TOKEN_RE = re.compile(r"^u(?P<user>\d+)a(?P<app>\d+)$")


def _resolve_uid(token: str) -> int | None:
    m = APP_UID_TOKEN_RE.match(token)
    if m:
        # Verified against real data: a package's "appId=NNNNN" field
        # already includes Android's +10000 app-UID-space offset (e.g.
        # appId=10358 for the app battery stats calls "u0a358" -- the "358"
        # in the token is the offset FROM 10000, not the appId itself).
        return int(m.group("user")) * 100000 + 10000 + int(m.group("app"))
    if token.isdigit():
        return int(token)
    return None


def parse_battery_uid_stats(section: Section) -> list[BatteryUidStats]:
    lines = section.lines
    n = len(lines)

    try:
        start = next(i for i, l in enumerate(lines) if l.strip() == POWER_USE_HEADER)
    except StopIteration:
        return []

    out: list[BatteryUidStats] = []
    i = start + 1
    while i < n:
        m = UID_HEADER_RE.match(lines[i])
        if not m:
            # Any other top-level (non-indented-continuation) line ends the
            # per-UID list -- e.g. a new "Global"/section header, or EOF.
            if lines[i].strip() and not lines[i].startswith((" ", "\t")):
                break
            i += 1
            continue

        token = m.group("token")
        uid = _resolve_uid(token)
        header_abs_line = section.line_start + i
        states = dict(STATE_FIELD_RE.findall(lines[i]))
        last_abs_line = header_abs_line

        components: dict[str, float] = {}
        j = i + 1
        while j < n and UID_HEADER_RE.match(lines[j]) is None and (lines[j].startswith((" ", "\t"))):
            for comp, val in COMPONENT_RE.findall(lines[j]):
                if comp not in components:  # first (top-of-block) value wins
                    components[comp] = float(val)
            last_abs_line = section.line_start + j
            j += 1

        if uid is not None:
            out.append(BatteryUidStats(
                uid_token=token, uid=uid, package=None,
                total_mah=float(m.group("total")),
                fg_mah=float(states["fg"]) if "fg" in states else None,
                bg_mah=float(states["bg"]) if "bg" in states else None,
                fgs_mah=float(states["fgs"]) if "fgs" in states else None,
                cached_mah=float(states["cached"]) if "cached" in states else None,
                components_mah=components,
                source_ref=SourceRef("batterystats", header_abs_line, last_abs_line),
            ))
        i = j

    return out
