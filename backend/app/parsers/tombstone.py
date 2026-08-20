"""Parser for plain-text native-crash tombstone files
(FS/data/tombstones/tombstone_NN inside the bugreport zip -- NOT the
flattened bugreport txt; these are separate files read directly from the
zip's own listing).

Real format (verified against actual tombstones):

    *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
    Build fingerprint: 'google/frankel/frankel:17/CP2A.260805.005/...'
    Kernel Release: '6.6.118-android15-...'
    Revision: 'MP1.0'
    ABI: 'arm64'
    Timestamp: 2026-08-12 09:39:40.192058775-0700
    Process uptime: 7117s
    Executable: /system/bin/app_process64
    Cmdline: com.google.android.gms:com.google.android.gms.chimera.IsolatedBoundBrokerService
    pid: 31108, ppid: 1446, tid: 31177, name: oxide-thread  >>> ... <<<
    uid: 99396
    ...
    signal 5 (SIGTRAP), code 1 (TRAP_BRKPT), fault addr 0x0000007b30abd3d8 (read)
    ...
    backtrace:
          #00 pc 000000000049b3d8  /data/app/.../base.apk!libbetocore.so (offset 0x8948000) (BuildId: ...)
          #01 pc ...

Cmdline varies: a reverse-domain package (optionally with a `:process`
suffix), a bare native executable path, or a full multi-token invocation
(e.g. a linker64 command line) -- package attribution is only made when the
first token looks like an actual Android package id, never guessed from
paths embedded deeper in the command line.
"""
from __future__ import annotations

import re

from app.parsers.base import TombstoneFacts

HEADER_RE = re.compile(r"^(?P<key>[A-Za-z ]+):\s*'?(?P<value>[^']*)'?\s*$")
PID_LINE_RE = re.compile(
    r"^pid:\s*(?P<pid>\d+),\s*(?:ppid:\s*\d+,\s*)?tid:\s*(?P<tid>\d+),\s*name:\s*(?P<name>\S+)"
)
UID_RE = re.compile(r"^uid:\s*(?P<uid>\d+)\s*$")
SIGNAL_RE = re.compile(
    r"^signal (?P<num>-?\d+) \((?P<name>[A-Z0-9]+)\), "
    r"code -?\d+ \((?P<code>\w+)\), fault addr (?P<addr>\S+)"
)
BACKTRACE_FRAME_RE = re.compile(r"^\s*#00\s+pc\s+\S+\s+(?P<frame>.+)$")

PACKAGE_LIKE_RE = re.compile(r"^[a-zA-Z][\w]*(\.[a-zA-Z][\w]*){2,}$")


def _derive_package(cmdline: str | None) -> str | None:
    if not cmdline:
        return None
    first_token = cmdline.split()[0] if cmdline.split() else cmdline
    if first_token.startswith("/"):
        return None  # native executable path, not an app package
    candidate = first_token.split(":")[0]
    return candidate if PACKAGE_LIKE_RE.match(candidate) else None


def parse_tombstone(filename: str, modified_at: str, text: str) -> TombstoneFacts:
    build_fingerprint = timestamp = executable = cmdline = abi = None
    pid = tid = uid = signal_number = None
    thread_name = signal_name = signal_code = fault_addr = top_frame = None

    for line in text.splitlines():
        if build_fingerprint is None:
            m = HEADER_RE.match(line)
            if m and m.group("key") == "Build fingerprint":
                build_fingerprint = m.group("value")
                continue
        if timestamp is None and line.startswith("Timestamp:"):
            timestamp = line.split(":", 1)[1].strip()
            continue
        if abi is None and line.startswith("ABI:"):
            abi = line.strip("ABI: '\n")
            continue
        if executable is None and line.startswith("Executable:"):
            executable = line.split(":", 1)[1].strip()
            continue
        if cmdline is None and line.startswith("Cmdline:"):
            cmdline = line.split(":", 1)[1].strip()
            continue
        if pid is None:
            m = PID_LINE_RE.match(line)
            if m:
                pid, tid, thread_name = int(m.group("pid")), int(m.group("tid")), m.group("name")
                continue
        if uid is None:
            m = UID_RE.match(line)
            if m:
                uid = int(m.group("uid"))
                continue
        if signal_number is None:
            m = SIGNAL_RE.match(line)
            if m:
                signal_number = int(m.group("num"))
                signal_name, signal_code, fault_addr = m.group("name"), m.group("code"), m.group("addr")
                continue
        if top_frame is None:
            m = BACKTRACE_FRAME_RE.match(line)
            if m:
                top_frame = m.group("frame").strip()
                continue

    return TombstoneFacts(
        filename=filename, modified_at=modified_at, timestamp=timestamp,
        build_fingerprint=build_fingerprint, executable=executable, cmdline=cmdline,
        package=_derive_package(cmdline), pid=pid, tid=tid, thread_name=thread_name, uid=uid,
        signal_number=signal_number, signal_name=signal_name, signal_code=signal_code,
        fault_addr=fault_addr, abi=abi, top_frame=top_frame,
    )
