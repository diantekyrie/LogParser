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
class ParsedCapture:
    """Everything a capture's ingestion pipeline produced, ground-truth facts only."""

    focus_stack: list[FocusStackEntry] = field(default_factory=list)
    focus_events: list[FocusEvent] = field(default_factory=list)
    packages: dict[str, PackageFacts] = field(default_factory=dict)
    media_sessions: list[MediaSessionFacts] = field(default_factory=list)
    foreground_services: list[ForegroundServiceFacts] = field(default_factory=list)
    parse_warnings: list[str] = field(default_factory=list)
