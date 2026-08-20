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
