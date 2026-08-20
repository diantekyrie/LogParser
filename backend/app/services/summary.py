"""Builds the dashboard summary for one capture: device info, fact counts,
top freeze/unfreeze offenders, and a merged chronological timeline of
everything with a timestamp (crashes, freeze/unfreeze, focus events). All
of it reads back rows already persisted at ingestion time -- nothing here
re-parses the bugreport.
"""
from __future__ import annotations

from sqlmodel import Session, func, select

from app.models.db_models import (
    Capture,
    CrashEventRow,
    DeviceInfoRow,
    FocusEventRow,
    FocusStackEntryRow,
    ForegroundServiceRow,
    FreezeSummaryRow,
    MediaSessionRow,
    NativeCrashFileRow,
    PackageFactRow,
)


def _source(section: str, start: int, end: int) -> dict:
    return {"section": section, "line_start": start, "line_end": end}


def build_capture_summary(session: Session, capture_id: int) -> dict:
    capture = session.get(Capture, capture_id)
    if capture is None:
        return {}

    device_info_row = session.exec(
        select(DeviceInfoRow).where(DeviceInfoRow.capture_id == capture_id)
    ).first()

    counts = {
        "packages": session.exec(
            select(func.count()).select_from(PackageFactRow).where(PackageFactRow.capture_id == capture_id)
        ).one(),
        "focus_events": session.exec(
            select(func.count()).select_from(FocusEventRow).where(FocusEventRow.capture_id == capture_id)
        ).one(),
        "focus_stack_entries": session.exec(
            select(func.count()).select_from(FocusStackEntryRow).where(FocusStackEntryRow.capture_id == capture_id)
        ).one(),
        "media_sessions": session.exec(
            select(func.count()).select_from(MediaSessionRow).where(MediaSessionRow.capture_id == capture_id)
        ).one(),
        "foreground_services": session.exec(
            select(func.count()).select_from(ForegroundServiceRow).where(ForegroundServiceRow.capture_id == capture_id)
        ).one(),
        "java_crashes": session.exec(
            select(func.count()).select_from(CrashEventRow).where(CrashEventRow.capture_id == capture_id)
        ).one(),
        "native_crashes": session.exec(
            select(func.count()).select_from(NativeCrashFileRow).where(NativeCrashFileRow.capture_id == capture_id)
        ).one(),
    }

    freeze_rows = session.exec(
        select(FreezeSummaryRow).where(FreezeSummaryRow.capture_id == capture_id)
    ).all()
    counts["freeze_events"] = sum(r.freeze_count for r in freeze_rows)
    counts["unfreeze_events"] = sum(r.unfreeze_count for r in freeze_rows)
    top_freeze_offenders = sorted(
        [{"package": r.package, "freezes": r.freeze_count, "unfreezes": r.unfreeze_count} for r in freeze_rows],
        key=lambda r: r["freezes"] + r["unfreezes"], reverse=True,
    )[:10]

    crash_rows = session.exec(
        select(CrashEventRow).where(CrashEventRow.capture_id == capture_id)
    ).all()
    native_crash_rows = session.exec(
        select(NativeCrashFileRow).where(NativeCrashFileRow.capture_id == capture_id)
    ).all()
    focus_event_rows = session.exec(
        select(FocusEventRow).where(FocusEventRow.capture_id == capture_id)
    ).all()

    timeline = []
    for c in crash_rows:
        timeline.append({
            "timestamp": c.timestamp, "kind": "crash", "severity": "critical",
            "label": f"{c.package or 'unknown'} crashed: {c.exception_class or 'exception'}",
            "source": _source(c.source_section, c.source_line_start, c.source_line_end),
        })
    for f in focus_event_rows:
        timeline.append({
            "timestamp": f.timestamp, "kind": "focus_event", "severity": "info",
            "label": f"{f.package}: {f.event_type}" + (f" ({f.detail})" if f.event_type == "owner_change" else ""),
            "source": _source(f.source_section, f.source_line_start, f.source_line_end),
        })
    timeline.sort(key=lambda e: e["timestamp"])

    media_session_rows = session.exec(
        select(MediaSessionRow).where(MediaSessionRow.capture_id == capture_id)
    ).all()
    focus_stack_rows = session.exec(
        select(FocusStackEntryRow).where(FocusStackEntryRow.capture_id == capture_id)
    ).all()

    return {
        "capture_id": capture.id,
        "original_filename": capture.original_filename,
        "ingested_at": capture.ingested_at.isoformat(),
        "parse_warnings": [w for w in capture.parse_warnings.split("\n") if w],
        "device_info": (
            {k: v for k, v in device_info_row.__dict__.items() if not k.startswith("_") and k not in ("id", "capture_id")}
            if device_info_row else None
        ),
        "counts": counts,
        "top_freeze_offenders": top_freeze_offenders,
        "native_crash_files": [{"filename": f.filename, "modified_at": f.modified_at} for f in native_crash_rows],
        "crash_events": [
            {
                "timestamp": c.timestamp, "package": c.package, "pid": c.pid,
                "exception_class": c.exception_class, "message": c.message,
                "root_cause_class": c.root_cause_class, "root_cause_message": c.root_cause_message,
                "root_cause_frame": c.root_cause_frame,
                "source": _source(c.source_section, c.source_line_start, c.source_line_end),
            } for c in crash_rows
        ],
        "timeline": timeline,
        "media_sessions": [
            {
                "package": m.package, "playback_state": m.playback_state,
                "active": m.active, "position_ms": m.position_ms,
                "source": _source(m.source_section, m.source_line_start, m.source_line_end),
            } for m in media_session_rows
        ],
        "focus_stack": [
            {
                "package": e.package, "uid": e.uid, "sdk": e.sdk, "gain": e.gain,
                "source": _source(e.source_section, e.source_line_start, e.source_line_end),
            } for e in focus_stack_rows
        ],
    }
