"""Parser for ANR (Application Not Responding) trace files
(FS/data/anr/anr_<timestamp> inside the bugreport zip -- separate files,
not text inside the flattened bugreport txt).

The first line is always:

    Subject: Process ProcessRecord{2e7636c 16041:com.disney.wdpro.dlr/u0a335} failed to complete startup

which alone gives pid, package, and the failure reason.
"""
from __future__ import annotations

import re

from app.parsers.base import AnrFacts

SUBJECT_RE = re.compile(
    r"^Subject: Process ProcessRecord\{[0-9a-f]+ (?P<pid>\d+):(?P<pkg>[\w.]+)/\S+\} (?P<reason>.+)$"
)

# Filenames look like "anr_2026-07-22-17-38-38-800"
FILENAME_TS_RE = re.compile(r"^anr_(?P<ts>[\d-]+)$")


def parse_anr(filename: str, text: str) -> AnrFacts:
    subject_line = text.splitlines()[0] if text else ""
    m = SUBJECT_RE.match(subject_line)

    ts_m = FILENAME_TS_RE.match(filename)
    timestamp = ts_m.group("ts") if ts_m else None

    return AnrFacts(
        filename=filename,
        timestamp=timestamp,
        subject=subject_line,
        pid=int(m.group("pid")) if m else None,
        package=m.group("pkg") if m else None,
        reason=m.group("reason") if m else None,
    )
