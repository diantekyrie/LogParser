from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlmodel import Session, select

from app.db import get_session
from app.llm import list_providers
from app.models.db_models import Capture, Device
from app.services.ingestion import parse_bugreport_zip
from app.services.persistence import persist_capture
from app.services.reasoning import diagnose
from app.services.summary import build_capture_summary

router = APIRouter()


@router.post("/captures")
async def upload_capture(
    device_label: str = Form(...),
    file: UploadFile = File(...),
    session: Session = Depends(get_session),
):
    if not file.filename.endswith(".zip"):
        raise HTTPException(400, "Expected a bugreport .zip upload")

    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = Path(tmp.name)

    try:
        parsed = parse_bugreport_zip(tmp_path)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(422, f"Failed to parse bugreport: {exc}") from exc
    finally:
        tmp_path.unlink(missing_ok=True)

    capture = persist_capture(session, device_label, file.filename, parsed)

    return {
        "capture_id": capture.id,
        "device_label": device_label,
        "parse_warnings": parsed.parse_warnings,
        "facts_found": {
            "focus_stack_entries": len(parsed.focus_stack),
            "focus_events": len(parsed.focus_events),
            "packages": len(parsed.packages),
            "media_sessions": len(parsed.media_sessions),
            "foreground_services": len(parsed.foreground_services),
        },
    }


@router.get("/llm/providers")
def get_llm_providers():
    return list_providers()


@router.get("/devices")
def list_devices(session: Session = Depends(get_session)):
    devices = session.exec(select(Device)).all()
    return devices


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
