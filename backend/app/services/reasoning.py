"""Assembles verified, source-cited facts into a diagnosis report.

Confidence is computed here, from how many independent structured facts
back a claim -- not by the LLM, and not from how assertively anything is
phrased. The LLM only narrates a fact bundle it's handed; it does not get
to invent a confidence level or introduce a claim that isn't already in the
bundle.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass

from sqlmodel import Session

from sqlmodel import select

from app.llm import get_llm_client
from app.models.db_models import AnrRow, CrashEventRow, TombstoneRow, WifiEventRow
from app.services.correlation import PackageHistory, package_history_across_device
from app.services.verification import EntityVerification, verify_question_entities

MULTI_CAPTURE_TRIGGER_RE = re.compile(
    r"\b(never|always|across|history|every capture|all captures|over time|"
    r"week|days|since|before)\b", re.IGNORECASE
)

CRASH_TRIGGER_RE = re.compile(r"\b(crash|crashed|crashing|anr|fatal|tombstone)\b", re.IGNORECASE)
WIFI_TRIGGER_RE = re.compile(r"\b(wi-?fi|wlan|disconnect|dropped|drop|roam)\w*\b", re.IGNORECASE)

SYSTEM_PROMPT = """You are a diagnosis-report writer for Android device logs.

You will be given a JSON bundle of ALREADY-VERIFIED structured facts, each
tagged with a confidence label and a source citation (section + line
numbers). Rules, no exceptions:

1. Never state a claim that is not present in the JSON bundle. If the
   bundle doesn't contain something, say it is unknown -- do not infer it.
2. Always carry each claim's given confidence label forward verbatim. Never
   upgrade "LOW" to "HIGH" because the underlying fact sounds compelling.
3. When the user's question frames one app as having caused a problem for
   another, report BOTH apps' own verified state, even if one of them
   undercuts the question's premise. Do not adopt the user's framing as
   fact.
4. Cite the section + line numbers for every factual claim you make.
5. If a fact was checked across multiple captures, say how many captures it
   was corroborated against, not just "confirmed."
6. If the bundle includes a top-level "device_wide_crash_evidence" key,
   that's crash/native-crash/ANR evidence for the WHOLE capture, not
   filtered to any named app -- use it to answer general crash/ANR
   questions, but never claim it proves a specific app crashed unless a
   claim's own crash_events/native_crashes/anrs says so. Native crashes
   carry a `package` field derived from the crashing process; when it's
   null, say attribution is unknown rather than guessing which app it was.
   Each entry carries its own "confidence" field, computed the same way as
   claim confidence -- use it verbatim, same as rule 2. Never assign a
   confidence level to anything in this bundle that isn't already labeled
   with one.
7. If the bundle includes a top-level "device_wide_wifi_evidence" key,
   that's every Wi-Fi disconnection event in the capture with its 802.11
   reason code -- Wi-Fi connectivity is device-wide, not per-app, so don't
   expect it to be attributed to any named app.
"""


@dataclass
class ScoredClaim:
    label: str            # human-readable claim
    confidence: str        # "HIGH" | "MEDIUM" | "LOW" | "UNCONFIRMED"
    corroboration: str     # explanation of what backs the confidence label
    source: dict | None


def score_confidence(fact_count: int, captures_checked: int) -> tuple[str, str]:
    """Confidence tied to corroboration, not phrasing. fact_count = number of
    independent structured facts backing the claim within one capture;
    captures_checked = how many captures in device history were checked.
    """
    if fact_count == 0:
        return "UNCONFIRMED", "No structured fact in this capture backs this claim; it is an unconfirmed hypothesis."
    if fact_count >= 2 and captures_checked >= 2:
        return "HIGH", f"Backed by {fact_count} independent structured facts, corroborated across {captures_checked} captures."
    if fact_count >= 2 or captures_checked >= 2:
        return "MEDIUM", f"Backed by {fact_count} structured fact(s), checked across {captures_checked} capture(s)."
    return "LOW", f"Backed by {fact_count} structured fact from a single capture only; not yet corroborated across history."


def build_entity_claim(ev: EntityVerification, history: PackageHistory | None) -> dict:
    fact_count = ev.corroborating_fact_count
    captures_checked = history.captures_checked if history else 1
    confidence, corroboration = score_confidence(fact_count, captures_checked)

    claim = {
        "package": ev.package,
        "matched_how": ev.matched_how,
        "confidence": confidence,
        "corroboration": corroboration,
        "verified_state": {
            "is_top_of_audio_focus_stack": ev.is_top_of_focus_stack,
            "media_session_active": ev.media_session_active,
            "media_session_playback_state": ev.media_session_playback_state,
            "media_session_position_ms": ev.media_session_position_ms,
            "media_session_source": ev.media_session_source,
            "latest_focus_event": ev.latest_focus_event,
            "target_sdk": ev.target_sdk,
            "target_sdk_source": ev.target_sdk_source,
            "crash_events": ev.crash_events,
            "freeze_count": ev.freeze_count,
            "unfreeze_count": ev.unfreeze_count,
            "native_crashes": ev.tombstones,
            "anrs": ev.anrs,
        },
    }
    if history is not None:
        claim["cross_capture_history"] = {
            "captures_checked": history.captures_checked,
            "ever_requested_audio_focus": history.ever_requested_focus,
            "focus_request_count_all_captures": history.focus_request_count,
            "target_sdk_by_capture": history.target_sdk_by_capture,
            "ever_hosted_foreground_service": history.ever_hosted_foreground_service,
        }
    return claim


def diagnose(
    session: Session, capture_id: int, device_label: str, question: str,
    provider: str | None = None,
) -> dict:
    entities = verify_question_entities(session, capture_id, question)
    want_history = bool(MULTI_CAPTURE_TRIGGER_RE.search(question))

    claims = []
    for ev in entities:
        history = package_history_across_device(session, device_label, ev.package) if want_history else None
        claims.append(build_entity_claim(ev, history))

    bundle = {
        "question": question,
        "entities_independently_verified": [c["package"] for c in claims],
        "claims": claims,
    }

    if CRASH_TRIGGER_RE.search(question):
        # Device-wide crash evidence, surfaced regardless of whether it's
        # attributable to a named app -- so a crash question never comes
        # back "unknown" when there's a real crash on the device that
        # simply wasn't named. Native crash files (tombstones) are binary;
        # we don't parse their contents, so which app crashed is honestly
        # reported as not determined by this system, not silently omitted.
        java_crash_count = session.exec(
            select(CrashEventRow).where(CrashEventRow.capture_id == capture_id)
        ).all()
        tombstone_count = session.exec(
            select(TombstoneRow).where(TombstoneRow.capture_id == capture_id)
        ).all()
        anr_count = session.exec(
            select(AnrRow).where(AnrRow.capture_id == capture_id)
        ).all()
        # Each event is exactly one structured fact, checked against exactly
        # this one capture -- computed the same way entity claims are,
        # rather than leaving confidence for the LLM to infer (an earlier
        # version left this field out entirely and relied on the system
        # prompt telling the model not to invent one; that worked for one
        # provider but not another live-tested one, which assigned "HIGH
        # confidence" to evidence that had none. Computing it removes the
        # ambiguity instead of hoping every model infers it the same way).
        crash_confidence, crash_corroboration = score_confidence(1, 1)
        bundle["device_wide_crash_evidence"] = {
            "note": "Not filtered to a named app -- includes every crash/ANR found in this capture.",
            "java_crashes": [
                {"timestamp": c.timestamp, "package": c.package, "exception_class": c.exception_class,
                 "message": c.message, "root_cause_class": c.root_cause_class,
                 "root_cause_message": c.root_cause_message, "root_cause_frame": c.root_cause_frame,
                 "confidence": crash_confidence, "corroboration": crash_corroboration,
                 "source": {"section": c.source_section, "line_start": c.source_line_start, "line_end": c.source_line_end}}
                for c in java_crash_count
            ],
            "native_crashes": [
                {"timestamp": t.timestamp, "package": t.package, "executable": t.executable,
                 "signal_name": t.signal_name, "signal_code": t.signal_code, "top_frame": t.top_frame,
                 "confidence": crash_confidence, "corroboration": crash_corroboration}
                for t in tombstone_count
            ],
            "native_crash_attribution_note": (
                "Tombstone `package` is derived from the crashing process's Cmdline; it is null "
                "when the process was a native binary/service rather than an app package -- that "
                "is reported as null, not guessed."
            ),
            "anrs": [
                {"timestamp": a.timestamp, "package": a.package, "reason": a.reason,
                 "confidence": crash_confidence, "corroboration": crash_corroboration}
                for a in anr_count
            ],
        }

    if WIFI_TRIGGER_RE.search(question):
        # Wi-Fi connectivity is device-wide, not attributable to a named
        # app, so this always surfaces regardless of whether any app was
        # named -- same principle as device_wide_crash_evidence.
        wifi_confidence, wifi_corroboration = score_confidence(1, 1)
        disconnections = session.exec(
            select(WifiEventRow).where(
                WifiEventRow.capture_id == capture_id, WifiEventRow.kind == "disconnection"
            )
        ).all()
        bundle["device_wide_wifi_evidence"] = {
            "note": "Every Wi-Fi disconnection event found in this capture, with its 802.11 reason code.",
            "disconnections": [
                {"timestamp": w.timestamp, "ssid": w.ssid, "bssid": w.bssid,
                 "reason_code": w.reason_code, "reason_name": w.reason_name,
                 "locally_generated": w.locally_generated,
                 "confidence": wifi_confidence, "corroboration": wifi_corroboration,
                 "source": {"section": w.source_section, "line_start": w.source_line_start, "line_end": w.source_line_end}}
                for w in disconnections
            ],
        }

    user_prompt = (
        "Verified fact bundle (JSON):\n\n" + json.dumps(bundle, indent=2, default=str) +
        "\n\nWrite a diagnosis report answering the question above using only these facts."
    )

    try:
        llm = get_llm_client(provider)
        report_text = llm.narrate(SYSTEM_PROMPT, user_prompt)
        llm_error = None
    except Exception as exc:  # noqa: BLE001 -- LLM narration is a convenience
        # layer on top of already-computed, independently verified facts.
        # A provider outage, quota error, or bad key should degrade to
        # "here are the facts, narration failed" -- never a 500 that hides
        # the verification work that already succeeded.
        report_text = None
        llm_error = str(exc)

    return {"bundle": bundle, "report": report_text, "llm_error": llm_error, "provider": provider}
