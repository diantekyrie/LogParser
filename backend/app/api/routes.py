from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlmodel import Session, select

from app.db import get_session
from app.llm import list_providers
from app.models.db_models import Capture, Device, Investigation, InvestigationCaptureLink
from app.services.ingestion import parse_capture_file
from app.services.persistence import persist_capture
from app.services.reasoning import diagnose
from app.services.summary import build_capture_summary

router = APIRouter()

SUPPORTED_UPLOAD_SUFFIXES = {".zip", ".txt", ".pcap", ".pcapng", ".btt"}


@router.post("/captures")
async def upload_capture(
    device_label: str = Form(...),
    investigation_label: str | None = Form(None),
    file: UploadFile = File(...),
    session: Session = Depends(get_session),
):
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in SUPPORTED_UPLOAD_SUFFIXES:
        raise HTTPException(400, "Expected one of: .zip, .txt, .pcap, .pcapng, .btt")

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = Path(tmp.name)

    try:
        parsed = parse_capture_file(tmp_path, file.filename)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(422, f"Failed to parse upload: {exc}") from exc
    finally:
        tmp_path.unlink(missing_ok=True)

    clean_investigation_label = investigation_label.strip() if investigation_label else None
    capture = persist_capture(
        session, device_label, file.filename, parsed,
        investigation_label=clean_investigation_label or None,
    )

    return {
        "capture_id": capture.id,
        "device_label": device_label,
        "investigation_label": clean_investigation_label,
        "parse_warnings": parsed.parse_warnings,
        "facts_found": {
            "focus_stack_entries": len(parsed.focus_stack),
            "focus_events": len(parsed.focus_events),
            "packages": len(parsed.packages),
            "media_sessions": len(parsed.media_sessions),
            "foreground_services": len(parsed.foreground_services),
            "packet_capture": parsed.packet_capture_summary is not None,
        },
    }


@router.get("/llm/providers")
def get_llm_providers():
    return list_providers()


@router.get("/devices")
def list_devices(session: Session = Depends(get_session)):
    devices = session.exec(select(Device)).all()
    return devices


@router.get("/investigations")
def list_investigations(session: Session = Depends(get_session)):
    return session.exec(select(Investigation)).all()


@router.get("/investigations/{investigation_label}/captures")
def list_investigation_captures(investigation_label: str, session: Session = Depends(get_session)):
    investigation = session.exec(
        select(Investigation).where(Investigation.label == investigation_label)
    ).first()
    if investigation is None:
        raise HTTPException(404, "Unknown investigation")
    captures = session.exec(
        select(Capture)
        .join(InvestigationCaptureLink, InvestigationCaptureLink.capture_id == Capture.id)
        .where(InvestigationCaptureLink.investigation_id == investigation.id)
    ).all()
    return captures


@router.get("/devices/{device_label}/captures")
def list_captures(device_label: str, session: Session = Depends(get_session)):
    device = session.exec(select(Device).where(Device.label == device_label)).first()
    if device is None:
        raise HTTPException(404, "Unknown device")
    captures = session.exec(select(Capture).where(Capture.device_id == device.id)).all()
    return captures


@router.get("/captures/{capture_id}/summary")
def capture_summary(capture_id: int, session: Session = Depends(get_session)):
    capture = session.get(Capture, capture_id)
    if capture is None:
        raise HTTPException(404, "Unknown capture")
    return build_capture_summary(session, capture_id)


@router.post("/captures/{capture_id}/diagnose")
def diagnose_capture(
    capture_id: int,
    question: str = Form(...),
    provider: str | None = Form(None),
    session: Session = Depends(get_session),
):
    capture = session.get(Capture, capture_id)
    if capture is None:
        raise HTTPException(404, "Unknown capture")
    device = session.get(Device, capture.device_id)

    result = diagnose(session, capture_id, device.label, question, provider=provider)
    return result
