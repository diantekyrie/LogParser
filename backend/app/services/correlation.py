"""Multi-capture correlation: the data model treats a device's captures as
one longitudinal history, not disposable single uploads. A finding like
"app X has never requested audio focus" is checked against every capture on
file for the device, not just whichever file happens to be in the current
request -- and the answer says how many captures it was checked against.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlmodel import Session, select

from app.models.db_models import Capture, Device, FocusEventRow, ForegroundServiceRow, PackageFactRow


@dataclass
class PackageHistory:
    package: str
    captures_checked: int
    ever_requested_focus: bool
    focus_request_count: int
    target_sdk_by_capture: dict[int, int | None]
    ever_hosted_foreground_service: bool


def captures_for_device(session: Session, device_label: str) -> list[Capture]:
    device = session.exec(select(Device).where(Device.label == device_label)).first()
    if device is None:
        return []
    return list(session.exec(
        select(Capture).where(Capture.device_id == device.id).order_by(Capture.ingested_at)
    ))


def package_history_across_device(session: Session, device_label: str, package: str) -> PackageHistory:
    """The check that would have turned "Disney+ apparently didn't request
    audio focus in this file" into a corroborated, multi-capture finding
    instead of a single-file guess.
    """
    captures = captures_for_device(session, device_label)
    capture_ids = [c.id for c in captures]

    request_count = 0
    target_sdk_by_capture: dict[int, int | None] = {}
    hosted_fgs = False

    if capture_ids:
        events = session.exec(
            select(FocusEventRow).where(
                FocusEventRow.capture_id.in_(capture_ids),
                FocusEventRow.package == package,
                FocusEventRow.event_type == "request",
            )
        ).all()
        request_count = len(events)

        for cid in capture_ids:
            row = session.exec(
                select(PackageFactRow).where(
                    PackageFactRow.capture_id == cid, PackageFactRow.package == package
                )
            ).first()
            target_sdk_by_capture[cid] = row.target_sdk if row else None

        fgs_row = session.exec(
            select(ForegroundServiceRow).where(
                ForegroundServiceRow.capture_id.in_(capture_ids),
                ForegroundServiceRow.package == package,
            )
        ).first()
        hosted_fgs = fgs_row is not None

    return PackageHistory(
        package=package,
        captures_checked=len(captures),
        ever_requested_focus=request_count > 0,
        focus_request_count=request_count,
        target_sdk_by_capture=target_sdk_by_capture,
        ever_hosted_foreground_service=hosted_fgs,
    )
