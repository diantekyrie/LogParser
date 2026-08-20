"""Writes a ParsedCapture's facts into the database as rows, one capture at
a time. Nothing here re-parses raw text; it only shapes already-parsed
dataclasses into SQL rows.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime

from sqlmodel import Session, select

from app.models.db_models import (
    AnrRow,
    BatteryUidStatRow,
    BtHciEventRow,
    BtHciSummaryRow,
    Capture,
    CrashEventRow,
    Device,
    DeviceInfoRow,
    FocusEventRow,
    FocusStackEntryRow,
    ForegroundServiceRow,
    FreezeSummaryRow,
    Investigation,
    InvestigationCaptureLink,
    MediaSessionRow,
    PackageFactRow,
    PacketCaptureSummaryRow,
    TombstoneRow,
    WifiEventRow,
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


def get_or_create_investigation(session: Session, investigation_label: str) -> Investigation:
    investigation = session.exec(
        select(Investigation).where(Investigation.label == investigation_label)
    ).first()
    if investigation is None:
        investigation = Investigation(label=investigation_label)
        session.add(investigation)
        session.commit()
        session.refresh(investigation)
    return investigation


def persist_capture(
    session: Session,
    device_label: str,
    original_filename: str,
    parsed: ParsedCapture,
    captured_at: datetime | None = None,
    investigation_label: str | None = None,
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

    if investigation_label:
        investigation = get_or_create_investigation(session, investigation_label)
        session.add(InvestigationCaptureLink(
            investigation_id=investigation.id,
            capture_id=capture.id,
        ))

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

    if parsed.device_info is not None:
        di = parsed.device_info
        session.add(DeviceInfoRow(
            capture_id=capture.id,
            manufacturer=di.manufacturer, model=di.model,
            android_release=di.android_release, sdk_version=di.sdk_version,
            build_id=di.build_id, build_fingerprint=di.build_fingerprint,
            security_patch=di.security_patch, bootloader=di.bootloader,
            radio=di.radio, network=di.network, kernel=di.kernel,
            serial=di.serial, cpu_abi=di.cpu_abi, hardware=di.hardware,
            build_type=di.build_type, uptime=di.uptime, timezone=di.timezone,
            crypto_state=di.crypto_state, verified_boot_state=di.verified_boot_state,
            debuggable=di.debuggable,
        ))

    for c in parsed.crash_events:
        session.add(CrashEventRow(
            capture_id=capture.id,
            timestamp=c.timestamp, thread=c.thread, package=c.package, pid=c.pid,
            exception_class=c.exception_class, message=c.message,
            root_cause_class=c.root_cause_class, root_cause_message=c.root_cause_message,
            root_cause_frame=c.root_cause_frame,
            source_section=c.source_ref.section,
            source_line_start=c.source_ref.line_start,
            source_line_end=c.source_ref.line_end,
        ))

    for t in parsed.tombstones:
        session.add(TombstoneRow(
            capture_id=capture.id, filename=t.filename, modified_at=t.modified_at,
            timestamp=t.timestamp, build_fingerprint=t.build_fingerprint,
            executable=t.executable, cmdline=t.cmdline, package=t.package,
            pid=t.pid, tid=t.tid, thread_name=t.thread_name, uid=t.uid,
            signal_number=t.signal_number, signal_name=t.signal_name,
            signal_code=t.signal_code, fault_addr=t.fault_addr, abi=t.abi,
            top_frame=t.top_frame,
        ))

    for a in parsed.anrs:
        session.add(AnrRow(
            capture_id=capture.id, filename=a.filename, timestamp=a.timestamp,
            subject=a.subject, pid=a.pid, package=a.package, reason=a.reason,
        ))

    if parsed.bt_hci_summary is not None:
        s = parsed.bt_hci_summary
        session.add(BtHciSummaryRow(
            capture_id=capture.id, total_packets=s.total_packets,
            command_count=s.command_count, event_count=s.event_count,
            acl_data_count=s.acl_data_count, first_timestamp=s.first_timestamp,
            last_timestamp=s.last_timestamp,
            event_code_counts_json=json.dumps(s.event_code_counts),
        ))
        for e in s.events:
            session.add(BtHciEventRow(
                capture_id=capture.id, timestamp=e.timestamp, kind=e.kind,
                status_code=e.status_code, status_name=e.status_name,
                handle=e.handle, reason_code=e.reason_code, reason_name=e.reason_name,
                opcode=e.opcode,
            ))

    if parsed.packet_capture_summary is not None:
        p = parsed.packet_capture_summary
        session.add(PacketCaptureSummaryRow(
            capture_id=capture.id, format=p.format, linktype=p.linktype,
            linktype_name=p.linktype_name, total_packets=p.total_packets,
            captured_bytes=p.captured_bytes, original_bytes=p.original_bytes,
            first_timestamp=p.first_timestamp, last_timestamp=p.last_timestamp,
            truncated_packets=p.truncated_packets, malformed_packets=p.malformed_packets,
        ))

    for w in parsed.wifi_events:
        session.add(WifiEventRow(
            capture_id=capture.id, timestamp=w.timestamp, kind=w.kind,
            ssid=w.ssid, bssid=w.bssid, reason_code=w.reason_code, reason_name=w.reason_name,
            locally_generated=w.locally_generated, roam=w.roam,
            source_section=w.source_ref.section,
            source_line_start=w.source_ref.line_start,
            source_line_end=w.source_ref.line_end,
        ))

    for b in parsed.battery_uid_stats:
        session.add(BatteryUidStatRow(
            capture_id=capture.id, uid_token=b.uid_token, uid=b.uid, package=b.package,
            total_mah=b.total_mah, fg_mah=b.fg_mah, bg_mah=b.bg_mah,
            fgs_mah=b.fgs_mah, cached_mah=b.cached_mah,
            components_mah_json=json.dumps(b.components_mah),
            source_section=b.source_ref.section,
            source_line_start=b.source_ref.line_start,
            source_line_end=b.source_ref.line_end,
        ))

    freeze_counts: Counter = Counter()
    unfreeze_counts: Counter = Counter()
    for e in parsed.freeze_events:
        (freeze_counts if e.event_type == "freeze" else unfreeze_counts)[e.package] += 1
    for pkg in set(freeze_counts) | set(unfreeze_counts):
        session.add(FreezeSummaryRow(
            capture_id=capture.id, package=pkg,
            freeze_count=freeze_counts.get(pkg, 0),
            unfreeze_count=unfreeze_counts.get(pkg, 0),
        ))

    session.commit()
    session.refresh(capture)
    return capture
