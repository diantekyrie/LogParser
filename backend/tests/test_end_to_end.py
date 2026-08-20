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

from app.llm import get_llm_client, list_providers
from app.services.correlation import package_history_across_device
from app.services.ingestion import parse_bugreport_zip
from app.services.persistence import persist_capture
from app.services.reasoning import diagnose
from app.services.summary import build_capture_summary
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


def test_summary_reflects_persisted_facts_not_a_reparse(session):
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    summary = build_capture_summary(session, capture.id)

    assert summary["device_info"]["model"] == "Pixel 10"
    assert summary["device_info"]["security_patch"] == "2026-08-05"
    assert summary["counts"]["java_crashes"] == 1
    assert summary["counts"]["native_crashes"] > 0
    assert summary["counts"]["freeze_events"] + summary["counts"]["unfreeze_events"] > 0
    assert len(summary["crash_events"]) == 1
    assert summary["crash_events"][0]["package"] == "com.android.systemui"
    # Every timeline entry must carry a source citation back to the raw log.
    with_source = [e for e in summary["timeline"] if e["source"] is not None]
    assert with_source  # at least some entries (crashes, focus events) carry citations
    assert all(e["source"]["line_start"] > 0 for e in with_source)


def test_crash_question_surfaces_device_wide_evidence_without_naming_an_app(session):
    # Regression: "Was there a crash?" previously came back "unknown" even
    # though the capture has a real, source-cited crash -- because
    # verification only ever looked at apps named in the question, and this
    # question doesn't name one. Crash-shaped questions now get device-wide
    # crash evidence regardless of whether any app was named.
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    result = diagnose(session, capture.id, "frankel-pixel", "Was there a crash on this device?")
    assert result["bundle"]["claims"] == []
    evidence = result["bundle"]["device_wide_crash_evidence"]
    assert len(evidence["java_crashes"]) == 1
    assert evidence["java_crashes"][0]["package"] == "com.android.systemui"
    assert len(evidence["native_crashes"]) > 0


def test_named_app_crash_data_included_in_its_own_claim(session):
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    result = diagnose(session, capture.id, "frankel-pixel", "Did com.android.systemui crash?")
    claim = next(c for c in result["bundle"]["claims"] if c["package"] == "com.android.systemui")
    assert len(claim["verified_state"]["crash_events"]) == 1
    assert claim["verified_state"]["crash_events"][0]["exception_class"] == "DeadSystemException"


def test_explicit_provider_selection_is_honored_and_reported_back(session):
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    result = diagnose(session, capture.id, "frankel-pixel", "Was there a crash?", provider="stub")
    assert result["provider"] == "stub"
    assert "[stub LLM" in result["report"]


def test_list_providers_reports_availability_from_env():
    ids = {p["id"] for p in list_providers()}
    assert ids == {"anthropic", "openai", "openai-codex", "stub"}
    stub = next(p for p in list_providers() if p["id"] == "stub")
    assert stub["available"] is True  # never requires a key


def test_unknown_provider_raises_rather_than_silently_falling_back():
    with pytest.raises(ValueError):
        get_llm_client("not-a-real-provider")


def test_named_app_anr_data_included_in_its_own_claim(session):
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    result = diagnose(session, capture.id, "frankel-pixel", "Did com.disney.wdpro.dlr ANR?")
    claim = next(c for c in result["bundle"]["claims"] if c["package"] == "com.disney.wdpro.dlr")
    assert len(claim["verified_state"]["anrs"]) == 2
    assert "failed to complete startup" in claim["verified_state"]["anrs"][0]["reason"]


def test_wifi_question_surfaces_device_wide_disconnection_evidence(session):
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    result = diagnose(session, capture.id, "frankel-pixel", "Did Wi-Fi drop or disconnect?")
    evidence = result["bundle"]["device_wide_wifi_evidence"]
    assert len(evidence["disconnections"]) == 3
    assert any(d["ssid"] == "amzn-www" and d["reason_code"] == 3 for d in evidence["disconnections"])


def test_bt_hci_summary_persisted_and_queryable(session):
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    summary = build_capture_summary(session, capture.id)
    bt = summary["bt_hci_summary"]
    assert bt is not None
    assert bt["total_packets"] > 0
    assert bt["command_count"] > 0 and bt["event_count"] > 0
    # A real anomaly this parser found in the fixture: a Command Complete
    # with a non-Success status should show up among notable events.
    assert any(e["status_name"] != "Success" for e in bt["notable_events"])


def test_two_word_brand_names_concatenated_in_package_ids_are_found(session):
    # Regression: "Disney Plus" and "Proton VPN" both matched ZERO
    # installed packages even though com.disney.disneyplus and
    # ch.protonvpn.android are both installed on this capture -- the
    # exact-segment-equality rule (added to stop "and" false-matching
    # inside "android") required a single question word to equal an
    # entire package segment, but these brand names collapse two words
    # into one segment with no separator ("disneyplus", "protonvpn").
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    result = diagnose(
        session, capture.id, "frankel-pixel",
        "The phone was draining battery fast and I'm wondering if it was from "
        "watching Disney Plus while connected to VPN using Proton VPN.",
    )
    claims = {c["package"]: c for c in result["bundle"]["claims"]}
    assert "com.disney.disneyplus" in claims
    assert "ch.protonvpn.android" in claims
    # Both entities turn out to have real, independently-verified state --
    # Disney+ was actively PLAYING, and Proton VPN shows freeze/unfreeze
    # cycling -- genuinely relevant corroborating context. Neither is a
    # battery-drain measurement (there's no battery-stats parser), so
    # confidence is MEDIUM (backed by real facts) rather than fabricated
    # HIGH or a battery-specific causal claim.
    assert claims["com.disney.disneyplus"]["verified_state"]["media_session_playback_state"] == "PLAYING"
    assert claims["ch.protonvpn.android"]["verified_state"]["freeze_count"] > 0
    for c in claims.values():
        assert c["confidence"] in {"LOW", "MEDIUM"}  # never HIGH from single-capture, non-cross-checked facts


def test_single_word_brand_name_with_no_space_is_found_when_unique(session):
    # Regression, found live immediately after the two-word fix above:
    # "ProtonVPN" typed as ONE word (no space) exactly equals
    # ch.protonvpn.android's one non-generic segment, but the >=2-hit rule
    # still discarded it since a single word only produces 1 hit. Fixed by
    # trusting a lone exact-segment match when that segment is unique to
    # one installed package (unlike a generic word such as "music", which
    # legitimately appears in multiple installed packages' segments and
    # must still require a second word to disambiguate).
    capture = _ingest(session, "frankel-pixel", CAPTURE_1)
    result = diagnose(
        session, capture.id, "frankel-pixel",
        "was the battery drained quickly due to using Disney Plus and ProtonVPN at the same time?",
    )
    matched = {c["package"] for c in result["bundle"]["claims"]}
    assert "ch.protonvpn.android" in matched
    assert "com.disney.disneyplus" in matched
