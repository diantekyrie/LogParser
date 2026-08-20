"""Shared types for parsed, structured facts pulled out of a bugreport.

Every fact carries a SourceRef so a diagnosis can cite the exact lines it
came from instead of asserting things the LLM can't point back to.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class SourceRef:
    """Points back at the exact place a fact was read from."""

    section: str          # e.g. "audio", "package", "media_session", "activity"
    line_start: int       # 1-indexed, absolute line number in the raw bugreport txt
    line_end: int

    def as_dict(self) -> dict:
        return {"section": self.section, "line_start": self.line_start, "line_end": self.line_end}


@dataclass
class FocusStackEntry:
    """One entry in the live 'Audio Focus stack entries' snapshot."""

    package: str
    uid: int
    client_id: str
    gain: str
    flags: str
    loss: str
    notified: Optional[bool]
    limbo: Optional[bool]
    sdk: Optional[int]
    attrs: str
    is_top_of_stack: bool
    source_ref: SourceRef


@dataclass
class FocusEvent:
    """One line from the MediaFocusControl event history."""

    timestamp: str          # raw "MM-DD HH:MM:SS:mmm" as printed, device-local
    event_type: str         # "request" | "abandon" | "owner_change"
    package: str
    uid: Optional[int]
    pid: Optional[int]
    usage: Optional[str]
    request_result: Optional[str]   # e.g. "1" (GRANTED) for request events
    loss_code: Optional[str]        # e.g. "-2" for handleLoss events
    detail: str                     # trailing free text (e.g. "handleLoss", "died")
    source_ref: SourceRef


@dataclass
class PackageFacts:
    package: str
    version_code: Optional[int]
    version_name: Optional[str]
    min_sdk: Optional[int]
    target_sdk: Optional[int]
    source_ref: SourceRef


@dataclass
class MediaSessionFacts:
    package: str
    session_tag: str
    active: bool
    playback_state: Optional[str]        # e.g. "PLAYING", "PAUSED"
    playback_state_code: Optional[int]
    position_ms: Optional[int]
    updated_at_elapsed_ms: Optional[int]  # SystemClock.elapsedRealtime() at last update
    is_media_button_session: bool
    source_ref: SourceRef


@dataclass
class ForegroundServiceFacts:
    package: str                      # package hosting the service
    service_class: str
    calling_package: Optional[str]    # who bound/started it (c: field)
    calling_uid: Optional[int]
    uid_state: Optional[str]          # e.g. "TOP", "CACC"
    proc_state: Optional[str]         # e.g. "PROC_STATE_TOP"
    target_sdk_version: Optional[int]
    caller_target_sdk_version: Optional[int]
    bfgs_denied: Optional[bool]
    source_ref: SourceRef


@dataclass
class ProcessFreezeEvent:
    """One `ActivityManager: freezing <pid> <process>` or
    `ActivityManager: sync unfroze <pid> <process> for <ms>` logcat line.
    The cached-process freezer is Android's mechanism for pausing
    background-process CPU/binder activity; a process stuck frozen (or
    thrashing freeze/unfreeze) is a common root cause of "app didn't
    respond to X" reports that isn't visible in any dumpsys snapshot.
    """

    timestamp: str                 # "MM-DD HH:MM:SS.mmm", device-local
    event_type: str                # "freeze" | "unfreeze"
    pid: int
    process: str                   # full process name, e.g. "com.android.vending:background"
    package: str                   # process name up to the first ':'
    # The trailing "for N" on an unfreeze line. N takes only a handful of
    # small values (observed: 1,3,4,6,7,10,19) -- that's a reason-code enum
    # from AOSP's CachedAppOptimizer, not a duration in ms. Reported as the
    # raw code rather than guessing/asserting a unit we haven't confirmed.
    unfreeze_reason_code: Optional[int]
    source_ref: SourceRef


@dataclass
class CrashEvent:
    """A Java `FATAL EXCEPTION` crash, parsed from the system log's
    AndroidRuntime lines:

        E AndroidRuntime: FATAL EXCEPTION: <thread>
        E AndroidRuntime: Process: <package>, PID: <pid>
        E AndroidRuntime: <ExceptionClass>: <message>
    """

    timestamp: str
    thread: str
    package: Optional[str]
    pid: Optional[int]
    exception_class: Optional[str]
    message: Optional[str]
    # The DEEPEST "Caused by:" exception in the chain -- usually the actual
    # root cause (e.g. a top-level "Unable to create application" wrapping
    # a third-party SDK's "Caused by: RuntimeException: 25"). None if the
    # crash had no "Caused by:" chain.
    root_cause_class: Optional[str]
    root_cause_message: Optional[str]
    root_cause_frame: Optional[str]  # first stack frame under the root cause, e.g. "com.foo.Bar.baz(Bar.java:69)"
    source_ref: SourceRef


@dataclass
class TombstoneFacts:
    """Parsed contents of one plain-text tombstone file
    (FS/data/tombstones/tombstone_NN) -- a native (non-JVM) crash dump.
    The `.pb` protobuf sibling of each tombstone is not parsed; the
    plain-text version carries the same facts in a directly-parseable form.
    """

    filename: str
    modified_at: str                   # as reported by the zip entry, device-local
    timestamp: Optional[str]           # device-local, as printed in the tombstone's own header
    build_fingerprint: Optional[str]
    executable: Optional[str]
    cmdline: Optional[str]
    package: Optional[str]             # derived from cmdline; None for native binaries
    pid: Optional[int]
    tid: Optional[int]
    thread_name: Optional[str]
    uid: Optional[int]
    signal_number: Optional[int]
    signal_name: Optional[str]         # e.g. "SIGSEGV"
    signal_code: Optional[str]         # e.g. "SEGV_MAPERR"
    fault_addr: Optional[str]
    abi: Optional[str]
    top_frame: Optional[str]           # first #00 backtrace line -- the crashing frame


@dataclass
class DeviceInfo:
    """Static device/build facts pulled from the bugreport's plain-text
    preamble and its `getprop` (SYSTEM PROPERTIES) dump. Every field is
    Optional -- a bugreport from a different OS version/vendor build may
    not print all of these, and an absent field is reported as unknown
    rather than guessed.
    """

    manufacturer: Optional[str] = None
    model: Optional[str] = None
    android_release: Optional[str] = None
    sdk_version: Optional[int] = None
    build_id: Optional[str] = None
    build_fingerprint: Optional[str] = None
    security_patch: Optional[str] = None
    bootloader: Optional[str] = None
    radio: Optional[str] = None
    network: Optional[str] = None
    kernel: Optional[str] = None
    serial: Optional[str] = None
    cpu_abi: Optional[str] = None
    hardware: Optional[str] = None
    build_type: Optional[str] = None
    uptime: Optional[str] = None
    timezone: Optional[str] = None
    crypto_state: Optional[str] = None
    verified_boot_state: Optional[str] = None
    debuggable: Optional[bool] = None


@dataclass
class AnrFacts:
    """Parsed contents of one ANR (Application Not Responding) trace file
    (FS/data/anr/anr_<timestamp> inside the bugreport zip -- a separate
    file, not text inside the flattened bugreport txt).

    The `Subject:` header line always has the shape:
        Process ProcessRecord{<hash> <pid>:<package>/<user>} <reason>
    e.g. "Process ProcessRecord{2e7636c 16041:com.disney.wdpro.dlr/u0a335}
    failed to complete startup" -- pid, package, and the failure reason are
    all pulled from this one line, which is always present.
    """

    filename: str
    timestamp: Optional[str]   # parsed from the filename, e.g. "2026-07-22-17-38-38-800"
    subject: str                # full raw Subject: line
    pid: Optional[int]
    package: Optional[str]
    reason: Optional[str]       # e.g. "failed to complete startup", "Input dispatching timed out"


@dataclass
class BtHciEvent:
    """One decoded HCI event/command-status/command-complete record from
    the device's `btsnoop`-format Bluetooth HCI log
    (FS/data/misc/bluetooth/logs/btsnooz_hci.log -- despite the filename,
    verified against real bytes to be the classic btsnoop binary format,
    not the compressed bugreport-inline "btsnooz" variant). Only the
    diagnostically load-bearing event types are decoded per-record
    (connection/disconnection complete, command complete/status, LE
    connection complete); everything else is counted in
    BtHciSummary.event_code_counts without per-record decoding.
    """

    timestamp: str          # ISO-ish UTC, converted from the btsnoop 64-bit epoch
    kind: str                # "disconnection_complete" | "connection_complete" |
                              # "command_complete" | "command_status" |
                              # "le_connection_complete"
    status_code: Optional[int]
    status_name: Optional[str]     # human label from the HCI status code table, or None if unmapped
    handle: Optional[int]
    reason_code: Optional[int]      # disconnection reason, same code table as status
    reason_name: Optional[str]
    opcode: Optional[int]           # command opcode, for command_complete/command_status


@dataclass
class BtHciSummary:
    """Aggregate facts from one capture's Bluetooth HCI log."""

    total_packets: int
    command_count: int
    event_count: int
    acl_data_count: int
    first_timestamp: Optional[str]
    last_timestamp: Optional[str]
    event_code_counts: dict          # {hex event code string: count}
    events: list[BtHciEvent] = field(default_factory=list)  # only the decoded high-value ones


@dataclass
class WifiEvent:
    """One decoded event from `DUMP OF SERVICE wifi` -> WifiController's
    state-machine transition log (`rec[N]: time=... what=EVENT_NAME ...`).
    Only the diagnostically load-bearing event types are decoded
    (disconnection with 802.11 reason code, BSSID association/roam);
    the state machine log has many other "what=" event types not parsed
    here (e.g. CMD_UPDATE_AP_CAPABILITY, screen state) since they carry no
    connectivity-failure signal.
    """

    timestamp: str
    kind: str                 # "disconnection" | "association"
    ssid: Optional[str]
    bssid: Optional[str]
    reason_code: Optional[int]        # 802.11 reason code, disconnection only
    reason_name: Optional[str]
    locally_generated: Optional[bool]  # disconnection only
    roam: Optional[bool]               # association only
    source_ref: SourceRef


@dataclass
class ParsedCapture:
    """Everything a capture's ingestion pipeline produced, ground-truth facts only."""

    focus_stack: list[FocusStackEntry] = field(default_factory=list)
    focus_events: list[FocusEvent] = field(default_factory=list)
    packages: dict[str, PackageFacts] = field(default_factory=dict)
    media_sessions: list[MediaSessionFacts] = field(default_factory=list)
    foreground_services: list[ForegroundServiceFacts] = field(default_factory=list)
    freeze_events: list[ProcessFreezeEvent] = field(default_factory=list)
    crash_events: list[CrashEvent] = field(default_factory=list)
    tombstones: list[TombstoneFacts] = field(default_factory=list)
    anrs: list[AnrFacts] = field(default_factory=list)
    bt_hci_summary: Optional[BtHciSummary] = None
    wifi_events: list[WifiEvent] = field(default_factory=list)
    device_info: Optional[DeviceInfo] = None
    parse_warnings: list[str] = field(default_factory=list)
