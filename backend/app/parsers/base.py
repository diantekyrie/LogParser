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
    source_ref: SourceRef


@dataclass
class NativeCrashFile:
    """A tombstone file present in the bugreport zip (FS/data/tombstones/).
    We report its existence and filename/timestamp -- these are binary
    native-crash dumps, not something this MVP parses the contents of."""

    filename: str
    modified_at: str  # as reported by the zip entry, device-local


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
class ParsedCapture:
    """Everything a capture's ingestion pipeline produced, ground-truth facts only."""

    focus_stack: list[FocusStackEntry] = field(default_factory=list)
    focus_events: list[FocusEvent] = field(default_factory=list)
    packages: dict[str, PackageFacts] = field(default_factory=dict)
    media_sessions: list[MediaSessionFacts] = field(default_factory=list)
    foreground_services: list[ForegroundServiceFacts] = field(default_factory=list)
    freeze_events: list[ProcessFreezeEvent] = field(default_factory=list)
    crash_events: list[CrashEvent] = field(default_factory=list)
    native_crash_files: list[NativeCrashFile] = field(default_factory=list)
    device_info: Optional[DeviceInfo] = None
    parse_warnings: list[str] = field(default_factory=list)
