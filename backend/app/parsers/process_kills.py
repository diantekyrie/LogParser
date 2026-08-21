"""Parser for ActivityManager process-kill events in the event log.

These are how memory pressure becomes visible: when the system needs RAM
it kills processes, and it records who, why, and at what OOM adjustment.
Real lines from a Pixel bugreport's EVENT LOG section:

    06-25 10:07:22.284 ... I am_kill : [0,8524,android.process.acore,935,Sync transaction while frozen,125168]
    06-25 00:48:35.804 ... I am_proc_died: [0,22891,com.android.providers.calendar,905,19]

`am_kill` fields are `[userId, pid, processName, oomAdj, reason, rssKb?]`.
The trailing RSS field only exists on newer Android builds, and the reason
is free text, so fields are taken from both ends (fixed fields from the
left, the optional numeric RSS from the right) with whatever remains
joined back as the reason -- rather than assuming a fixed field count or
that the reason never contains a comma.

`am_proc_died` fields are `[userId, pid, processName, oomAdj, procState]`
and record a death without a kill reason: the process went away, but this
line alone does not say the system killed it deliberately. The two are
parsed into the same shape with a `kind` discriminator so they can be
counted together as "processes that went away" while keeping the
distinction that only am_kill carries an actual reason.

OOM adjustment is the scheduler's killability score: roughly 0 for
foreground/critical processes and up toward ~1000 for empty cached ones.
It is reported as the raw number without a "this was safe/unsafe to kill"
interpretation, which depends on Android version and device policy.
"""
from __future__ import annotations

import re

from app.parsers.base import ProcessKillEvent, SourceRef
from app.parsers.section_extractor import Section

KILL_LINE_RE = re.compile(
    r"^(?P<ts>\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+\S+\s+\d+\s+\d+ "
    r"[VDIWEF] (?P<tag>am_kill|am_proc_died)\s*:\s*\[(?P<body>.*)\]\s*$"
)


def _int_or_none(value: str) -> int | None:
    value = value.strip()
    try:
        return int(value)
    except ValueError:
        return None


def parse_process_kills(section: Section) -> list[ProcessKillEvent]:
    out: list[ProcessKillEvent] = []
    for i, raw in enumerate(section.lines):
        m = KILL_LINE_RE.match(raw)
        if not m:
            continue
        fields = m.group("body").split(",")
        if len(fields) < 4:
            continue  # malformed / unexpected shape -- skipped, never guessed at

        tag = m.group("tag")
        user_id = _int_or_none(fields[0])
        pid = _int_or_none(fields[1])
        process = fields[2].strip()
        oom_adj = _int_or_none(fields[3])

        reason: str | None = None
        rss_kb: int | None = None
        proc_state: int | None = None

        if tag == "am_kill":
            tail = fields[4:]
            # Newer builds append an RSS value; older ones stop at the
            # reason. Only treat a trailing field as RSS when it is purely
            # numeric AND something remains for the reason -- otherwise a
            # reason that happens to be a bare number would vanish.
            if len(tail) >= 2 and tail[-1].strip().isdigit():
                rss_kb = _int_or_none(tail[-1])
                reason = ",".join(tail[:-1]).strip()
            elif tail:
                reason = ",".join(tail).strip()
        else:  # am_proc_died
            proc_state = _int_or_none(fields[4]) if len(fields) > 4 else None

        abs_line = section.line_start + i
        out.append(ProcessKillEvent(
            timestamp=m.group("ts"),
            kind="kill" if tag == "am_kill" else "died",
            user_id=user_id,
            pid=pid,
            process=process,
            # An Android process name can be "pkg:subprocess" (e.g.
            # "com.android.chrome:sandboxed_process0"); the package is the
            # part before the colon.
            package=process.split(":")[0] if process else None,
            oom_adj=oom_adj,
            reason=reason or None,
            rss_kb=rss_kb,
            proc_state=proc_state,
            source_ref=SourceRef(section.name, abs_line, abs_line),
        ))
    return out
