"""Parser for `DUMP OF SERVICE activity` -> ServiceRecord / foreground-service
state, including the `infoAllowStartForeground=[...]` block that (among
other things) carries each service's targetSdkVersion and caller's
targetSdkVersion at bind/start time.
"""
from __future__ import annotations

import re

from app.parsers.base import ForegroundServiceFacts, SourceRef
from app.parsers.section_extractor import Section

# "  * ServiceRecord{3991bac u0 com.apple.android.music/org.chromium.content.app.SandboxedProcessService0:0 c:com.apple.android.music}"
SERVICE_RECORD_RE = re.compile(
    r"^\s*\*\s*ServiceRecord\{[0-9a-f]+ u\d+ (?P<pkg>[\w.\-]+)/(?P<cls>\S+)(?: c:(?P<caller>[\w.\-]+))?\}\s*$"
)

# infoAllowStartForeground=[callingPackage: X; callingUid: N; uidState: S ; ... BFGS denied: bool; ...
#   ...code:PROC_STATE_X; ...targetSdkVersion:N; callerTargetSdkVersion:N; ...]
INFO_ALLOW_RE = re.compile(r"infoAllowStartForeground=\[(?P<body>.*)\]\s*$")

FIELD_RES = {
    "calling_package": re.compile(r"callingPackage:\s*([\w.\-]+)"),
    "calling_uid": re.compile(r"callingUid:\s*(\d+)"),
    "uid_state": re.compile(r"uidState:\s*(\S+)"),
    "bfgs_denied": re.compile(r"BFGS denied:\s*(true|false)"),
    "proc_state": re.compile(r"\bcode:(PROC_STATE_\w+|\w+)"),
    "target_sdk_version": re.compile(r"targetSdkVersion:\s*(\d+)"),
    "caller_target_sdk_version": re.compile(r"callerTargetSdkVersion:\s*(\d+)"),
}


def parse_foreground_services(section: Section) -> list[ForegroundServiceFacts]:
    lines = section.lines
    n = len(lines)
    out: list[ForegroundServiceFacts] = []

    i = 0
    while i < n:
        m = SERVICE_RECORD_RE.match(lines[i])
        if not m:
            i += 1
            continue

        pkg = m.group("pkg")
        cls = m.group("cls")
        caller = m.group("caller")
        header_abs_line = section.line_start + i

        calling_package = caller
        calling_uid = uid_state = proc_state = None
        target_sdk = caller_target_sdk = None
        bfgs_denied = None
        info_abs_line = header_abs_line

        # infoAllowStartForeground, when present, appears within the next
        # ~60 lines of this ServiceRecord's block, before the next record.
        j = i + 1
        limit = min(n, i + 80)
        while j < limit and not SERVICE_RECORD_RE.match(lines[j]):
            info_m = INFO_ALLOW_RE.search(lines[j])
            if info_m:
                body = info_m.group("body")
                info_abs_line = section.line_start + j
                cp = FIELD_RES["calling_package"].search(body)
                if cp:
                    calling_package = cp.group(1)
                cu = FIELD_RES["calling_uid"].search(body)
                if cu:
                    calling_uid = int(cu.group(1))
                us = FIELD_RES["uid_state"].search(body)
                if us:
                    uid_state = us.group(1)
                bd = FIELD_RES["bfgs_denied"].search(body)
                if bd:
                    bfgs_denied = bd.group(1) == "true"
                ps = FIELD_RES["proc_state"].search(body)
                if ps:
                    proc_state = ps.group(1)
                ts = FIELD_RES["target_sdk_version"].search(body)
                if ts:
                    target_sdk = int(ts.group(1))
                cts = FIELD_RES["caller_target_sdk_version"].search(body)
                if cts:
                    caller_target_sdk = int(cts.group(1))
                break
            j += 1

        out.append(ForegroundServiceFacts(
            package=pkg,
            service_class=cls,
            calling_package=calling_package,
            calling_uid=calling_uid,
            uid_state=uid_state,
            proc_state=proc_state,
            target_sdk_version=target_sdk,
            caller_target_sdk_version=caller_target_sdk,
            bfgs_denied=bfgs_denied,
            source_ref=SourceRef("activity", header_abs_line, info_abs_line),
        ))
        i += 1

    return out
