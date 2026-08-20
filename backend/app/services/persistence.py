"""Writes a ParsedCapture's facts into the database as rows, one capture at
a time. Nothing here re-parses raw text; it only shapes already-parsed
dataclasses into SQL rows.
"""
from __future__ import annotations

from datetime import datetime

from sqlmodel import Session, select

from app.models.db_models import (
    Capture,
    Device,
    FocusEventRow,
    FocusStackEntryRow,
    ForegroundServiceRow,
    MediaSessionRow,
    PackageFactRow,
)
from app.parsers.base import ParsedCapture


def get_or_create_device(session: Session, device_label: str) -> Device:
    device = session.exec(select(Device).where(Device.label == device_label)).first()
    if device is None:
        device = Device(label=device_label)
        session.add(device)
        session.commit()
        session.refresh(device)
    return device


def persist_capture(
    session: Session,
    device_label: str,
    original_filename: str,
    parsed: ParsedCapture,
    captured_at: datetime | None = None,
) -> Capture:
    device = get_or_create_device(session, device_label)

    capture = Capture(
        device_id=device.id,
        original_filename=original_filename,
        captured_at=captured_at,
        parse_warnings="\n".join(parsed.parse_warnings),
    )
    session.add(capture)
    session.commit()
    session.refresh(capture)

    for e in parsed.focus_stack:
        session.add(FocusStackEntryRow(
            capture_id=capture.id,
            package=e.package, uid=e.uid, client_id=e.client_id,
            gain=e.gain, flags=e.flags, loss=e.loss,
            notified=e.notified, limbo=e.limbo, sdk=e.sdk, attrs=e.attrs,
            is_top_of_stack=e.is_top_of_stack,
            source_section=e.source_ref.section,
            source_line_start=e.source_ref.line_start,
            source_line_end=e.source_ref.line_end,
        ))

    for e in parsed.focus_events:
        session.add(FocusEventRow(
            capture_id=capture.id,
            timestamp=e.timestamp, event_type=e.event_type, package=e.package,
            uid=e.uid, pid=e.pid, usage=e.usage,
            request_result=e.request_result, loss_code=e.loss_code, detail=e.detail,
            source_section=e.source_ref.section,
            source_line_start=e.source_ref.line_start,
            source_line_end=e.source_ref.line_end,
        ))

    for pkg, p in parsed.packages.items():
        session.add(PackageFactRow(
            capture_id=capture.id,
            package=pkg, version_code=p.version_code, version_name=p.version_name,
            min_sdk=p.min_sdk, target_sdk=p.target_sdk,
            source_section=p.source_ref.section,
            source_line_start=p.source_ref.line_start,
            source_line_end=p.source_ref.line_end,
        ))

    for m in parsed.media_sessions:
        session.add(MediaSessionRow(
            capture_id=capture.id,
            package=m.package, session_tag=m.session_tag, active=m.active,
            playback_state=m.playback_state, playback_state_code=m.playback_state_code,
            position_ms=m.position_ms, updated_at_elapsed_ms=m.updated_at_elapsed_ms,
            is_media_button_session=m.is_media_button_session,
            source_section=m.source_ref.section,
            source_line_start=m.source_ref.line_start,
            source_line_end=m.source_ref.line_end,
        ))

    for f in parsed.foreground_services:
        session.add(ForegroundServiceRow(
            capture_id=capture.id,
            package=f.package, service_class=f.service_class,
            calling_package=f.calling_package, calling_uid=f.calling_uid,
            uid_state=f.uid_state, proc_state=f.proc_state,
            target_sdk_version=f.target_sdk_version,
            caller_target_sdk_version=f.caller_target_sdk_version,
            bfgs_denied=f.bfgs_denied,
            source_section=f.source_ref.section,
            source_line_start=f.source_ref.line_start,
            source_line_end=f.source_ref.line_end,
        ))

    session.commit()
    session.refresh(capture)
    return capture
