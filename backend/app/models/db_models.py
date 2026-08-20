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


class NativeCrashFileRow(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    filename: str
    modified_at: str


class FreezeSummaryRow(SQLModel, table=True):
    """Per-package freeze/unfreeze counts for one capture. Individual
    freeze/unfreeze events aren't persisted row-by-row (a capture can have
    thousands); this is the aggregate the dashboard actually needs."""

    id: Optional[int] = Field(default=None, primary_key=True)
    capture_id: int = Field(foreign_key="capture.id", index=True)
    package: str = Field(index=True)
    freeze_count: int
    unfreeze_count: int
