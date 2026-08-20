"""End-to-end pipeline test against the real fixtures: parse -> persist ->
verify named entities -> multi-capture correlation -> diagnosis bundle.

Uses an in-memory SQLite DB so it doesn't touch the real groundtruth.db.
Runs the case study from the build brief: does the system independently
verify the "victim" app's own state, does it find the focus stack without
hedging, and does a "never requested focus" claim get checked across every
capture on file for the device rather than just the current upload.
"""
from pathlib import Path

import pytest
from sqlmodel import Session, SQLModel, create_engine

from app.services.correlation import package_history_across_device
from app.services.ingestion import parse_bugreport_zip
from app.services.persistence import persist_capture
from app.services.reasoning import diagnose
from app.services.verification import verify_question_entities

FIXTURES = Path(__file__).parent / "fixtures"
CAPTURE_1 = FIXTURES / "bugreport_2026-08-13.zip"
CAPTURE_2 = FIXTURES / "bugreport_2026-08-19.zip"

pytestmark = pytest.mark.skipif(not CAPTURE_1.exists(), reason="real bugreport fixtures not present")


@pytest.fixture
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _ingest(session, device_label, path):
    parsed = parse_bugreport_zip(path)
    return persist_capture(session, device_label, path.name, parsed)


def test_verification_surfaces_both_named_apps_independently(session):
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)

    question = "Did YouTube Music fail to pause when Apple Music started playing?"
    entities = verify_question_entities(session, capture.id, question)
    matched = {e.package for e in entities}

    # Both the "accused" and the app that started playing get independently
    # checked -- the question's framing is not taken as given.
    assert "com.google.android.apps.youtube.music" in matched
    assert "com.apple.android.music" in matched

    yt = next(e for e in entities if e.package == "com.google.android.apps.youtube.music")
    # Ground truth: YouTube Music's own MediaSession state shows PAUSED,
    # contradicting a premise that it was playing and failed to pause.
    assert yt.media_session_playback_state == "PAUSED"
    assert yt.media_session_source is not None  # citable


def test_focus_stack_found_without_hedging(session):
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    entities = verify_question_entities(session, capture.id, "com.apple.android.music focus")
    top = next(e for e in entities if e.package == "com.apple.android.music")
    assert top.is_top_of_focus_stack is True


def test_multi_capture_correlation_checks_full_history(session):
    _ingest(session, "frankel-pixel", CAPTURE_1)
    if CAPTURE_2.exists():
        _ingest(session, "frankel-pixel", CAPTURE_2)
        expected_captures = 2
    else:
        expected_captures = 1

    history = package_history_across_device(session, "frankel-pixel", "com.disney.disneyplus")
    assert history.captures_checked == expected_captures
    # Whatever the finding, it must say how many captures backed it --
    # never a silent single-file guess dressed up as a stronger claim.


def test_diagnose_returns_confidence_tied_to_corroboration(session):
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    result = diagnose(
        session, capture.id, "frankel-pixel",
        "Has com.disney.disneyplus ever requested audio focus across all captures?",
    )
    claims = result["bundle"]["claims"]
    assert len(claims) >= 1
    for c in claims:
        assert c["confidence"] in {"HIGH", "MEDIUM", "LOW", "UNCONFIRMED"}
        assert "cross_capture_history" in c  # "across all captures" triggered history lookup
    assert "[stub LLM" in result["report"]
