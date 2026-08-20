"""Persisted structured facts. Every parsed capture's facts land here as
rows, not as a raw blob re-parsed on every query -- that's what makes
"across all captures for this device" a plain SQL query instead of a
re-parse of every uploaded zip.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlmodel import Field, SQLModel


class Device(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    label: str = Field(index=True, unique=True)  # user-chosen identifier, e.g. serial or nickname
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Capture(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    device_id: int = Field(foreign_key="device.id", index=True)
    original_filename: str
    captured_at: Optional[datetime] = None   # parsed from the bugreport's own timestamp, if known
    ingested_at: datetime = Field(default_factory=datetime.utcnow)
    parse_warnings: str = ""                 # newline-joined; empty string = clean parse


class FocusStackEntryRow(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    package: str = Field(index=True)
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
    source_section: str
    source_line_start: int
    source_line_end: int


class FocusEventRow(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    timestamp: str
    event_type: str
    package: str = Field(index=True)
    uid: Optional[int]
    pid: Optional[int]
    usage: Optional[str]
    request_result: Optional[str]
    loss_code: Optional[str]
    detail: str
    source_section: str
    source_line_start: int
    source_line_end: int


class PackageFactRow(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    package: str = Field(index=True)
    version_code: Optional[int]
    version_name: Optional[str]
    min_sdk: Optional[int]
    target_sdk: Optional[int]
    source_section: str
    source_line_start: int
    source_line_end: int


class MediaSessionRow(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    package: str = Field(index=True)
    session_tag: str
    active: bool
    playback_state: Optional[str]
    playback_state_code: Optional[int]
    position_ms: Optional[int]
    updated_at_elapsed_ms: Optional[int]
    is_media_button_session: bool
    source_section: str
    source_line_start: int
    source_line_end: int


class ForegroundServiceRow(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    package: str = Field(index=True)
    service_class: str
    calling_package: Optional[str] = Field(default=None, index=True)
    calling_uid: Optional[int]
    uid_state: Optional[str]
    proc_state: Optional[str]
    target_sdk_version: Optional[int]
    caller_target_sdk_version: Optional[int]
    bfgs_denied: Optional[bool]
    source_section: str
    source_line_start: int
    source_line_end: int


class DeviceInfoRow(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True, unique=True)
    manufacturer: Optional[str]
    model: Optional[str]
    android_release: Optional[str]
    sdk_version: Optional[int]
    build_id: Optional[str]
    build_fingerprint: Optional[str]
    security_patch: Optional[str]
    bootloader: Optional[str]
    radio: Optional[str]
    network: Optional[str]
    kernel: Optional[str]
    serial: Optional[str]
    cpu_abi: Optional[str]
    hardware: Optional[str]
    build_type: Optional[str]
    uptime: Optional[str]
    timezone: Optional[str]
    crypto_state: Optional[str]
    verified_boot_state: Optional[str]
    debuggable: Optional[bool]


class CrashEventRow(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    timestamp: str
    thread: str
    package: Optional[str] = Field(default=None, index=True)
    pid: Optional[int]
    exception_class: Optional[str]
    message: Optional[str]
    root_cause_class: Optional[str]
    root_cause_message: Optional[str]
    root_cause_frame: Optional[str]
    source_section: str
    source_line_start: int
    source_line_end: int


class TombstoneRow(SQLModel, table=True):
    """A parsed native (non-JVM) crash -- content, not just filename/mtime."""

    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    filename: str
    modified_at: str
    timestamp: Optional[str]
    build_fingerprint: Optional[str]
    executable: Optional[str]
    cmdline: Optional[str]
    package: Optional[str] = Field(default=None, index=True)
    pid: Optional[int]
    tid: Optional[int]
    thread_name: Optional[str]
    uid: Optional[int]
    signal_number: Optional[int]
    signal_name: Optional[str]
    signal_code: Optional[str]
    fault_addr: Optional[str]
    abi: Optional[str]
    top_frame: Optional[str]


class AnrRow(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    filename: str
    timestamp: Optional[str]
    subject: str
    pid: Optional[int]
    package: Optional[str] = Field(default=None, index=True)
    reason: Optional[str]


class BtHciSummaryRow(SQLModel, table=True):
    """One row per capture: aggregate Bluetooth HCI log facts."""

    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True, unique=True)
    total_packets: int
    command_count: int
    event_count: int
    acl_data_count: int
    first_timestamp: Optional[str]
    last_timestamp: Optional[str]
    event_code_counts_json: str  # JSON-encoded {hex code: count}


class BtHciEventRow(SQLModel, table=True):
    """One decoded high-value HCI event (connection/disconnection/command
    complete/status) -- see app/parsers/bt_hci.py for which event types
    get per-record decoding."""

    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    timestamp: str
    kind: str = Field(index=True)
    status_code: Optional[int]
    status_name: Optional[str]
    handle: Optional[int]
    reason_code: Optional[int]
    reason_name: Optional[str]
    opcode: Optional[int]


class BatteryUidStatRow(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    uid_token: str
    uid: int
    package: Optional[str] = Field(default=None, index=True)
    total_mah: float
    fg_mah: Optional[float]
    bg_mah: Optional[float]
    fgs_mah: Optional[float]
    cached_mah: Optional[float]
    components_mah_json: str
    source_section: str
    source_line_start: int
    source_line_end: int


class WifiEventRow(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    timestamp: str
    kind: str = Field(index=True)
    ssid: Optional[str]
    bssid: Optional[str]
    reason_code: Optional[int]
    reason_name: Optional[str]
    locally_generated: Optional[bool]
    roam: Optional[bool]
    source_section: str
    source_line_start: int
    source_line_end: int


class FreezeSummaryRow(SQLModel, table=True):
    """Per-package freeze/unfreeze counts for one capture. Individual
    freeze/unfreeze events aren't persisted row-by-row (a capture can have
    thousands); this is the aggregate the dashboard actually needs."""

    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    package: str = Field(index=True)
    freeze_count: int
    unfreeze_count: int
