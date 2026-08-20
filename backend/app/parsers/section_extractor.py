"""Streams the (typically 100-250MB) flattened bugreport .txt out of the zip
and slices out only the `dumpsys` sections we have parsers for.

We never load the whole bugreport into memory. `dumpsys` output inside a
bugreport is delimited like:

    DUMP OF SERVICE [CRITICAL|HIGH] <name>:
    ...content...
    --------- 0.002s was the duration of dumpsys <name>, ending at: <ts>
    -------------------------------------------------------------------------------

The same service name can appear multiple times (a fast CRITICAL/HIGH pass
early in the bugreport, then the full dump later) -- when that happens we
keep the LAST occurrence, since in every real bugreport observed the later,
un-prioritized dump is the complete one.
"""
from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field

SECTION_START_RE = re.compile(r"^DUMP OF SERVICE(?: (CRITICAL|HIGH))? ([\w./+\-]+):\s*$")
SECTION_END_RE = re.compile(r"^--------- .* was the duration of dumpsys ")

MAIN_ENTRY_RE = re.compile(r"^bugreport-.*\.txt$")


@dataclass
class Section:
    name: str
    priority: str | None     # None | "CRITICAL" | "HIGH"
    line_start: int          # first line of content (after the header line)
    line_end: int            # last line of content (inclusive, before the footer)
    lines: list[str] = field(default_factory=list)


def find_main_bugreport_entry(zf: zipfile.ZipFile) -> zipfile.ZipInfo:
    """The flattened bugreport txt is the top-level bugreport-*.txt entry.

    There are other .txt files inside FS/ and proto/ trees; the real one is
    at the archive root and is by far the largest.
    """
    candidates = [
        info for info in zf.infolist()
        if "/" not in info.filename and MAIN_ENTRY_RE.match(info.filename)
    ]
    if not candidates:
        raise ValueError("No top-level bugreport-*.txt entry found in zip")
    return max(candidates, key=lambda i: i.file_size)


def extract_sections(zf: zipfile.ZipFile, wanted_names: set[str]) -> dict[str, Section]:
    """Stream the main bugreport txt once, returning the last occurrence of
    each wanted DUMP OF SERVICE section.
    """
    entry = find_main_bugreport_entry(zf)
    results: dict[str, Section] = {}

    current: Section | None = None
    line_no = 0

    with zf.open(entry) as raw:
        # newline="\n": split ONLY on '\n', matching how every other tool
        # (grep, the line numbers cited in a hand-inspected bugreport, etc.)
        # counts lines. Universal-newlines mode (the default) also treats a
        # bare '\r' as a line break, and bugreports embed plenty of stray
        # '\r' bytes from native crash/tombstone dumps -- that silently
        # drifts every subsequent line number and misattributes citations.
        text_stream = io.TextIOWrapper(raw, encoding="utf-8", errors="replace", newline="\n")
        for line in text_stream:
            line_no += 1
            stripped = line.rstrip("\n").rstrip("\r")

            if current is None:
                m = SECTION_START_RE.match(stripped)
                if m and m.group(2) in wanted_names:
                    current = Section(
                        name=m.group(2),
                        priority=m.group(1),
                        line_start=line_no + 1,
                        line_end=line_no + 1,
                    )
                continue

            # We are inside a wanted section; watch for its end marker.
            if SECTION_END_RE.match(stripped):
                current.line_end = line_no - 1
                # Keep the LAST occurrence of a given section name.
                results[current.name] = current
                current = None
                continue

            current.lines.append(stripped)

    if current is not None:
        # File ended mid-section (shouldn't happen in a well-formed bugreport).
        current.line_end = line_no
        results[current.name] = current

    return results
