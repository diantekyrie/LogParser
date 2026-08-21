"""Builds the dashboard summary for one capture: device info, fact counts,
top freeze/unfreeze offenders, and a merged chronological timeline of
everything with a timestamp (crashes, freeze/unfreeze, focus events, ANRs,
tombstones, Bluetooth HCI events). All of it reads back rows already
persisted at ingestion time -- nothing here re-parses the bugreport.
"""
from __future__ import annotations

import json

from sqlmodel import Session, func, select

from app.models.db_models import (
    AnrRow,
    BatteryUidStatRow,
    BtHciEventRow,
    BtHciSummaryRow,
    Capture,
    CrashEventRow,
    DeviceInfoRow,
    FocusEventRow,
    FocusStackEntryRow,
    ForegroundServiceRow,
    FreezeSummaryRow,
    MediaSessionRow,
    PackageFactRow,
    PacketAnalysisRow,
    PacketCaptureSummaryRow,
    TombstoneRow,
    WifiEventRow,
)


def _source(section: str, start: int, end: int) -> dict:
    return {"section": section, "line_start": start, "line_end": end}


def capture_severity(session: Session, capture_id: int) -> dict:
    """Cheap counts used to badge a capture in a list (sidebar, investigation
    picker) before it's actually opened -- not a substitute for the full
    summary, just enough to answer "does this one need attention."
    """
    java_crashes = len(session.exec(select(CrashEventRow).where(CrashEventRow.capture_id == capture_id)).all())
    native_crashes = len(session.exec(select(TombstoneRow).where(TombstoneRow.capture_id == capture_id)).all())
    anrs = len(session.exec(select(AnrRow).where(AnrRow.capture_id == capture_id)).all())
    wifi_disconnects = len(session.exec(
        select(WifiEventRow).where(WifiEventRow.capture_id == capture_id, WifiEventRow.kind == "disconnection")
    ).all())
    return {
        "java_crashes": java_crashes,
        "native_crashes": native_crashes,
        "anrs": anrs,
        "wifi_disconnects": wifi_disconnects,
        "has_findings": (java_crashes + native_crashes + anrs + wifi_disconnects) > 0,
    }


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
            select(func.count()).select_from(TombstoneRow).where(TombstoneRow.capture_id == capture_id)
        ).one(),
        "anrs": session.exec(
            select(func.count()).select_from(AnrRow).where(AnrRow.capture_id == capture_id)
        ).one(),
        "wifi_disconnections": session.exec(
            select(func.count()).select_from(WifiEventRow)
            .where(WifiEventRow.capture_id == capture_id, WifiEventRow.kind == "disconnection")
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
    tombstone_rows = session.exec(
        select(TombstoneRow).where(TombstoneRow.capture_id == capture_id)
    ).all()
    anr_rows = session.exec(
        select(AnrRow).where(AnrRow.capture_id == capture_id)
    ).all()
    focus_event_rows = session.exec(
        select(FocusEventRow).where(FocusEventRow.capture_id == capture_id)
    ).all()
    bt_summary_row = session.exec(
        select(BtHciSummaryRow).where(BtHciSummaryRow.capture_id == capture_id)
    ).first()
    packet_summary_row = session.exec(
        select(PacketCaptureSummaryRow).where(PacketCaptureSummaryRow.capture_id == capture_id)
    ).first()
    packet_analysis_row = session.exec(
        select(PacketAnalysisRow).where(PacketAnalysisRow.capture_id == capture_id)
    ).first()
    bt_event_rows = session.exec(
        select(BtHciEventRow).where(BtHciEventRow.capture_id == capture_id)
    ).all()
    wifi_event_rows = session.exec(
        select(WifiEventRow).where(WifiEventRow.capture_id == capture_id)
    ).all()
    battery_rows = session.exec(
        select(BatteryUidStatRow)
        .where(BatteryUidStatRow.capture_id == capture_id)
        .order_by(BatteryUidStatRow.total_mah.desc())
        .limit(15)
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
    for a in anr_rows:
        timeline.append({
            "timestamp": a.timestamp or "", "kind": "anr", "severity": "critical",
            "label": f"{a.package or 'unknown'} ANR: {a.reason or a.subject}",
            "source": None,
        })
    for t in tombstone_rows:
        timeline.append({
            "timestamp": t.timestamp or "", "kind": "native_crash", "severity": "critical",
            "label": f"{t.package or t.executable or 'unknown'} native crash: {t.signal_name or 'signal'}"
                     + (f" ({t.signal_code})" if t.signal_code else ""),
            "source": None,
        })
    for e in bt_event_rows:
        if e.kind == "disconnection_complete" or (e.status_code and e.status_code != 0):
            label = f"BT {e.kind.replace('_', ' ')}"
            if e.status_name:
                label += f": {e.status_name}"
            if e.reason_name:
                label += f" (reason: {e.reason_name})"
            timeline.append({
                "timestamp": e.timestamp, "kind": "bt_hci",
                "severity": "warning" if (e.status_code or 0) != 0 else "info",
                "label": label, "source": None,
            })
    for w in wifi_event_rows:
        if w.kind == "disconnection":
            timeline.append({
                "timestamp": w.timestamp, "kind": "wifi",
                "severity": "info" if w.locally_generated else "warning",
                "label": f"Wi-Fi disconnected from {w.ssid}: {w.reason_name}"
                         + (" (locally initiated)" if w.locally_generated else ""),
                "source": _source(w.source_section, w.source_line_start, w.source_line_end),
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
        "crash_events": [
            {
                "timestamp": c.timestamp, "package": c.package, "pid": c.pid,
                "exception_class": c.exception_class, "message": c.message,
                "root_cause_class": c.root_cause_class, "root_cause_message": c.root_cause_message,
                "root_cause_frame": c.root_cause_frame,
                "source": _source(c.source_section, c.source_line_start, c.source_line_end),
            } for c in crash_rows
        ],
        "tombstones": [
            {
                "filename": t.filename, "modified_at": t.modified_at, "timestamp": t.timestamp,
                "package": t.package, "executable": t.executable, "signal_name": t.signal_name,
                "signal_code": t.signal_code, "fault_addr": t.fault_addr, "top_frame": t.top_frame,
            } for t in tombstone_rows
        ],
        "anrs": [
            {
                "filename": a.filename, "timestamp": a.timestamp, "package": a.package,
                "pid": a.pid, "reason": a.reason, "subject": a.subject,
            } for a in anr_rows
        ],
        "bt_hci_summary": (
            {
                "total_packets": bt_summary_row.total_packets,
                "command_count": bt_summary_row.command_count,
                "event_count": bt_summary_row.event_count,
                "acl_data_count": bt_summary_row.acl_data_count,
                "first_timestamp": bt_summary_row.first_timestamp,
                "last_timestamp": bt_summary_row.last_timestamp,
                "event_code_counts": json.loads(bt_summary_row.event_code_counts_json),
                "notable_events": [
                    {
                        "timestamp": e.timestamp, "kind": e.kind, "status_name": e.status_name,
                        "reason_name": e.reason_name, "handle": e.handle,
                    }
                    for e in bt_event_rows
                    if e.kind == "disconnection_complete" or (e.status_code or 0) != 0
                ],
            } if bt_summary_row else None
        ),
        "packet_capture_summary": (
            {
                "format": packet_summary_row.format,
                "linktype": packet_summary_row.linktype,
                "linktype_name": packet_summary_row.linktype_name,
                "total_packets": packet_summary_row.total_packets,
                "captured_bytes": packet_summary_row.captured_bytes,
                "original_bytes": packet_summary_row.original_bytes,
                "first_timestamp": packet_summary_row.first_timestamp,
                "last_timestamp": packet_summary_row.last_timestamp,
                "truncated_packets": packet_summary_row.truncated_packets,
                "malformed_packets": packet_summary_row.malformed_packets,
            } if packet_summary_row else None
        ),
        "packet_analysis": (
            {
                "backend": packet_analysis_row.backend,
                "link_layer": packet_analysis_row.link_layer,
                "packets_analyzed": packet_analysis_row.packets_analyzed,
                "retry_count": packet_analysis_row.retry_count,
                "retry_rate_pct": packet_analysis_row.retry_rate_pct,
                "rssi_min_dbm": packet_analysis_row.rssi_min_dbm,
                "rssi_max_dbm": packet_analysis_row.rssi_max_dbm,
                "rssi_avg_dbm": packet_analysis_row.rssi_avg_dbm,
                "note": packet_analysis_row.note,
                "frame_type_breakdown": json.loads(packet_analysis_row.frame_type_breakdown_json),
                "identity_signals": json.loads(packet_analysis_row.identity_signals_json),
                "anomalies": json.loads(packet_analysis_row.anomalies_json),
            } if packet_analysis_row else None
        ),
        "wifi_events": [
            {
                "timestamp": w.timestamp, "kind": w.kind, "ssid": w.ssid, "bssid": w.bssid,
                "reason_code": w.reason_code, "reason_name": w.reason_name,
                "locally_generated": w.locally_generated, "roam": w.roam,
                "source": _source(w.source_section, w.source_line_start, w.source_line_end),
            } for w in wifi_event_rows
        ],
        "top_battery_consumers": [
            {
                "package": b.package, "uid_token": b.uid_token, "total_mah": b.total_mah,
                "fg_mah": b.fg_mah, "bg_mah": b.bg_mah, "fgs_mah": b.fgs_mah, "cached_mah": b.cached_mah,
                "components_mah": json.loads(b.components_mah_json),
                "source": _source(b.source_section, b.source_line_start, b.source_line_end),
            } for b in battery_rows
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
