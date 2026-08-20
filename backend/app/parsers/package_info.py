"""Parser for `DUMP OF SERVICE package` -> per-package blocks.

Pulls targetSdk/minSdk/versionCode/versionName for every installed package.
This is the fact logcat.ai left as a manual "you should check this" step
even though it was sitting in the same file it was analyzing -- here it's
extracted unconditionally for every package so it's always available to the
reasoning layer, unprompted.
"""
from __future__ import annotations

import re

from app.parsers.base import PackageFacts, SourceRef
from app.parsers.section_extractor import Section

# "  Package [com.apple.android.music] (2459f93):"
PACKAGE_HEADER_RE = re.compile(r"^\s{2}Package \[(?P<pkg>[\w.\-]+)\] \([0-9a-f]+\):\s*$")

# "    versionCode=1583 minSdk=30 targetSdk=35"
VERSION_LINE_RE = re.compile(
    r"^\s*versionCode=(?P<vc>\d+)(?:\s+minSdk=(?P<min>\d+))?(?:\s+targetSdk=(?P<tgt>\d+))?"
)

VERSION_NAME_RE = re.compile(r"^\s*versionName=(?P<vn>\S+)\s*$")


def parse_packages(section: Section) -> dict[str, PackageFacts]:
    lines = section.lines
    n = len(lines)
    out: dict[str, PackageFacts] = {}

    i = 0
    while i < n:
        m = PACKAGE_HEADER_RE.match(lines[i])
        if not m:
            i += 1
            continue

        pkg = m.group("pkg")
        header_abs_line = section.line_start + i
        version_code = min_sdk = target_sdk = None
        version_name = None
        last_field_abs_line = header_abs_line

        j = i + 1
        while j < n and not PACKAGE_HEADER_RE.match(lines[j]):
            vm = VERSION_LINE_RE.match(lines[j])
            if vm:
                version_code = int(vm.group("vc"))
                if vm.group("min"):
                    min_sdk = int(vm.group("min"))
                if vm.group("tgt"):
                    target_sdk = int(vm.group("tgt"))
                last_field_abs_line = section.line_start + j
            vnm = VERSION_NAME_RE.match(lines[j])
            if vnm:
                version_name = vnm.group("vn")
                last_field_abs_line = section.line_start + j
            j += 1

        out[pkg] = PackageFacts(
            package=pkg,
            version_code=version_code,
            version_name=version_name,
            min_sdk=min_sdk,
            target_sdk=target_sdk,
            source_ref=SourceRef("package", header_abs_line, last_field_abs_line),
        )
        i = j

    return out
