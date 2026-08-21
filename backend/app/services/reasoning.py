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
from app.models.db_models import (
    AnrRow,
    BatteryUidStatRow,
    BtHciEventRow,
    BtHciSummaryRow,
    CdmPairingEventRow,
    Capture,
    CompanionDeviceAssociationRow,
    CrashEventRow,
    Device,
    PacketAnalysisRow,
    PacketCaptureSummaryRow,
    TombstoneRow,
    WifiEventRow,
)
from app.services.correlation import PackageHistory, package_history_across_device
from app.services.verification import EntityVerification, verify_question_entities

MULTI_CAPTURE_TRIGGER_RE = re.compile(
    r"\b(never|always|across|history|every capture|all captures|over time|"
    r"week|days|since|before)\b", re.IGNORECASE
)

CRASH_TRIGGER_RE = re.compile(r"\b(crash|crashed|crashing|anr|fatal|tombstone)\b", re.IGNORECASE)
# Real gap found live: a "was there a network issue on these devices" question
# didn't match this trigger at all (no "wifi"/"disconnect"/"drop"/"roam"
# token), so device_wide_wifi_evidence never made it into the bundle even
# though the capture had a real Wi-Fi disconnection event with an 802.11
# reason code sitting in it. Two different LLM providers then both honestly
# (and correctly, given their bundle) said "no wifi evidence present" --
# which was true of the bundle but not of the capture. "network"/"internet"
# added so a network-flavored question always at least checks for Wi-Fi
# disconnects, same principle as the pairing-trigger gap fixed earlier.
WIFI_TRIGGER_RE = re.compile(
    r"\b(wi-?fi|wlan|disconnect|dropped|drop|roam|network|internet)\w*\b", re.IGNORECASE
)
BATTERY_TRIGGER_RE = re.compile(r"\b(battery|drain(?:ed|ing)?|power|mah)\b", re.IGNORECASE)
PAIRING_TRIGGER_RE = re.compile(
    r"\b(pair(?:ed|ing)?|bond(?:ed|ing)?|bluetooth|\bbt\b|companion|network|connect(?:ed|ion)?)\b",
    re.IGNORECASE,
)

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
6. Every "device_wide_*" evidence key (crash, wifi, battery, pairing --
   rules 6-9 below) is gathered across EVERY capture on file for this
   device, not just the one the question happened to be asked against --
   each individual entry in these lists carries its own "capture_id" and
   "original_filename" saying which capture it actually came from, and you
   must cite that alongside the section/line number (rule 4) so a fact
   found in a different capture than the one named in the question is
   never presented as if it came from "this capture." Their confidence
   already reflects how many captures were checked (rule 2's "carry it
   forward verbatim" still applies -- do not recompute or upgrade it).
7. If the bundle includes a top-level "device_wide_crash_evidence" key,
   that's crash/native-crash/ANR evidence across every capture for this
   device, not filtered to any named app -- use it to answer general
   crash/ANR questions, but never claim it proves a specific app crashed
   unless a claim's own crash_events/native_crashes/anrs says so. Native
   crashes carry a `package` field derived from the crashing process; when
   it's null, say attribution is unknown rather than guessing which app it
   was. Never assign a confidence level to anything in this bundle that
   isn't already labeled with one.
8. If the bundle includes a top-level "device_wide_wifi_evidence" key,
   that's every Wi-Fi disconnection event across every capture for this
   device with its 802.11 reason code -- Wi-Fi connectivity is device-wide,
   not per-app, so don't expect it to be attributed to any named app.
9. If the bundle includes a top-level "device_wide_battery_evidence" key,
   or a claim's verified_state has a "battery" field, that's real
   estimated-mAh attribution across every capture for this device, broken
   down by component (cpu/screen/audio/wifi/mobile_radio/wakelock/etc). It
   is a snapshot for each capture's own stats window, not a measured
   cause-and-effect link to any specific user-reported symptom -- report
   the numbers plainly and let them speak for themselves rather than
   asserting they "caused" drain unless the bundle itself frames it that
   way.
10. If the bundle includes "device_wide_pairing_evidence", those are real
    Companion Device Manager / Fast Pair events across every capture for
    this device. A "kind":"anomaly" entry means only that the log level
    (W/E) flagged it, not that its `detail` text has been independently
    interpreted -- quote the detail rather than paraphrasing a cause into
    it. "bt_hci_summary", "packet_capture_summary", and "packet_analysis",
    when present, are each a LIST with one entry per capture that has that
    kind of data (also capture-tagged) -- supporting evidence, not
    necessarily about the same capture as a given pairing event.
    packet_capture_summary is container-level metadata only (packet
    count/time range) and cannot by itself identify what happened.
    packet_analysis is real protocol-level dissection -- its "backend"
    field on each entry says whether it came from full tshark dissection
    or the narrower hand-rolled fallback (see that entry's own "note"
    field for exactly what that backend does and doesn't cover, e.g. the
    fallback backend does not decode deauth/disassoc reason codes or
    detect TCP retransmissions -- never state a reason code or
    retransmission fact unless a packet_analysis entry actually contains
    one). Frame counts, RSSI range, retry rate, SSIDs/BSSIDs, and any
    listed anomalies in packet_analysis are real per-packet facts, not
    inferred. If "device_wide_pairing_evidence" includes a
    "current_associations" list, that's the CDM service's OWN
    current-state record of each paired device at the moment ITS capture
    was taken -- not reconstructed from log messages, so it's the most
    direct answer to "is this device currently paired/connected"
    available in this bundle (check which capture it's tagged with).
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
            "battery": ev.battery,
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


def build_diagnosis_bundle(session: Session, capture_id: int, device_label: str, question: str) -> dict:
    """Everything diagnose() needs except the actual LLM call -- pulled out
    so investigation-level diagnosis (see diagnose_investigation()) can
    build one bundle per capture and merge them before a single LLM call,
    without duplicating the per-capture fact-gathering logic.
    """
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

    # Real gap found live: "device-wide" evidence (crash/wifi/battery/
    # pairing, below) was actually scoped to just the ONE capture_id passed
    # in -- so asking the identical question against two different captures
    # uploaded for the same device (e.g. a phone's bugreport vs. a watch's,
    # both filed under one shared device label) could come back with
    # completely different answers depending purely on which capture
    # happened to be selected in the UI at the time, even though both were
    # "the same device"'s data. Every block below now searches every
    # capture on file for this device, not just the selected one, and tags
    # each individual fact with which capture it actually came from so
    # citations stay traceable. Confidence is upgraded accordingly by
    # captures_checked (see score_confidence) -- checking N captures for a
    # device-wide fact is real corroboration, not just checking one.
    device = session.exec(select(Device).where(Device.label == device_label)).first()
    sibling_captures = (
        session.exec(select(Capture).where(Capture.device_id == device.id)).all()
        if device else []
    )
    sibling_capture_ids = [c.id for c in sibling_captures] or [capture_id]
    capture_filenames = {c.id: c.original_filename for c in sibling_captures}
    captures_checked = len(sibling_capture_ids)

    def _capture_tag(row_capture_id: int) -> dict:
        return {"capture_id": row_capture_id, "original_filename": capture_filenames.get(row_capture_id)}

    if CRASH_TRIGGER_RE.search(question):
        # Device-wide crash evidence, surfaced regardless of whether it's
        # attributable to a named app -- so a crash question never comes
        # back "unknown" when there's a real crash on the device that
        # simply wasn't named. Native crash files (tombstones) are binary;
        # we don't parse their contents, so which app crashed is honestly
        # reported as not determined by this system, not silently omitted.
        java_crash_count = session.exec(
            select(CrashEventRow).where(CrashEventRow.capture_id.in_(sibling_capture_ids))
        ).all()
        tombstone_count = session.exec(
            select(TombstoneRow).where(TombstoneRow.capture_id.in_(sibling_capture_ids))
        ).all()
        anr_count = session.exec(
            select(AnrRow).where(AnrRow.capture_id.in_(sibling_capture_ids))
        ).all()
        # Each event is exactly one structured fact -- computed the same way
        # entity claims are, rather than leaving confidence for the LLM to
        # infer (an earlier version left this field out entirely and relied
        # on the system prompt telling the model not to invent one; that
        # worked for one provider but not another live-tested one, which
        # assigned "HIGH confidence" to evidence that had none. Computing it
        # removes the ambiguity instead of hoping every model infers it the
        # same way). captures_checked reflects every capture actually
        # searched for this device, not just the one that happened to be
        # selected.
        crash_confidence, crash_corroboration = score_confidence(1, captures_checked)
        bundle["device_wide_crash_evidence"] = {
            "note": (
                f"Not filtered to a named app -- includes every crash/ANR found across all "
                f"{captures_checked} capture(s) on file for this device, each tagged with which "
                f"capture it came from."
            ),
            "java_crashes": [
                {"timestamp": c.timestamp, "package": c.package, "exception_class": c.exception_class,
                 "message": c.message, "root_cause_class": c.root_cause_class,
                 "root_cause_message": c.root_cause_message, "root_cause_frame": c.root_cause_frame,
                 "confidence": crash_confidence, "corroboration": crash_corroboration,
                 **_capture_tag(c.capture_id),
                 "source": {"section": c.source_section, "line_start": c.source_line_start, "line_end": c.source_line_end}}
                for c in java_crash_count
            ],
            "native_crashes": [
                {"timestamp": t.timestamp, "package": t.package, "executable": t.executable,
                 "signal_name": t.signal_name, "signal_code": t.signal_code, "top_frame": t.top_frame,
                 "confidence": crash_confidence, "corroboration": crash_corroboration,
                 **_capture_tag(t.capture_id)}
                for t in tombstone_count
            ],
            "native_crash_attribution_note": (
                "Tombstone `package` is derived from the crashing process's Cmdline; it is null "
                "when the process was a native binary/service rather than an app package -- that "
                "is reported as null, not guessed."
            ),
            "anrs": [
                {"timestamp": a.timestamp, "package": a.package, "reason": a.reason,
                 "confidence": crash_confidence, "corroboration": crash_corroboration,
                 **_capture_tag(a.capture_id)}
                for a in anr_count
            ],
        }

    if WIFI_TRIGGER_RE.search(question):
        # Wi-Fi connectivity is device-wide, not attributable to a named
        # app, so this always surfaces regardless of whether any app was
        # named -- same principle as device_wide_crash_evidence.
        wifi_confidence, wifi_corroboration = score_confidence(1, captures_checked)
        disconnections = session.exec(
            select(WifiEventRow).where(
                WifiEventRow.capture_id.in_(sibling_capture_ids), WifiEventRow.kind == "disconnection"
            )
        ).all()
        bundle["device_wide_wifi_evidence"] = {
            "note": (
                f"Every Wi-Fi disconnection event found across all {captures_checked} capture(s) on "
                f"file for this device (not just the one currently selected), with its 802.11 reason "
                f"code and which capture it came from."
            ),
            "disconnections": [
                {"timestamp": w.timestamp, "ssid": w.ssid, "bssid": w.bssid,
                 "reason_code": w.reason_code, "reason_name": w.reason_name,
                 "locally_generated": w.locally_generated,
                 "confidence": wifi_confidence, "corroboration": wifi_corroboration,
                 **_capture_tag(w.capture_id),
                 "source": {"section": w.source_section, "line_start": w.source_line_start, "line_end": w.source_line_end}}
                for w in disconnections
            ],
        }

    if BATTERY_TRIGGER_RE.search(question):
        # Battery attribution is per-UID, not automatically tied to a named
        # app in the question -- surfaced device-wide (top consumers) so a
        # battery question always gets real evidence, same principle as
        # crash/wifi triggers. Live-tested gap this closes: a battery-drain
        # question naming two apps used to come back "no battery data
        # exists in this bundle" even when the parsed capture had real
        # per-app mAh attribution the whole time -- there was simply no
        # battery-stats parser wiring it into the bundle at all.
        battery_confidence, battery_corroboration = score_confidence(1, captures_checked)
        top_consumers = session.exec(
            select(BatteryUidStatRow)
            .where(BatteryUidStatRow.capture_id.in_(sibling_capture_ids))
            .order_by(BatteryUidStatRow.total_mah.desc())
            .limit(15)
        ).all()
        bundle["device_wide_battery_evidence"] = {
            "note": (
                f"Top battery consumers by estimated mAh across all {captures_checked} capture(s) "
                f"on file for this device, not filtered to a named app. `package` is null for UIDs "
                f"that are shared by multiple system packages (e.g. the \"system\" UID) or have no "
                f"matching installed package -- attribution is not guessed in that case."
            ),
            "top_consumers": [
                {"package": b.package, "uid_token": b.uid_token, "total_mah": b.total_mah,
                 "components_mah": json.loads(b.components_mah_json),
                 "confidence": battery_confidence, "corroboration": battery_corroboration,
                 **_capture_tag(b.capture_id),
                 "source": {"section": b.source_section, "line_start": b.source_line_start, "line_end": b.source_line_end}}
                for b in top_consumers
            ],
        }

    if PAIRING_TRIGGER_RE.search(question):
        # Real gap found live: a "network error while pairing" question
        # between two devices came back "unknown" from two different LLM
        # providers, even though the actual pairing session -- Fast Pair
        # discovery, Companion Device Manager association, secure-channel
        # handshake -- was sitting in the system log the whole time, along
        # with a concrete, repeated failure
        # ("Action REQUEST_TRANSPORT FAILED to activate") that a generic
        # W/E-level catch-all found even though it wasn't hand-anticipated.
        # Also include the raw Bluetooth HCI and packet-capture summaries
        # here (previously computed and shown on the dashboard but never
        # actually reached the LLM bundle at all) since a pairing/network
        # question is exactly when they're relevant.
        pairing_confidence, pairing_corroboration = score_confidence(1, captures_checked)
        pairing_events = session.exec(
            select(CdmPairingEventRow).where(CdmPairingEventRow.capture_id.in_(sibling_capture_ids))
        ).all()
        bundle["device_wide_pairing_evidence"] = {
            "note": (
                f"Companion Device Manager / Fast Pair events across all {captures_checked} "
                f"capture(s) on file for this device, not filtered to a named app. "
                f"kind=\"anomaly\" entries are any W/E-level CDM_* log line whose specific "
                "message wasn't individually decoded -- the log level flags it as worth attention, "
                "the raw text is in `detail`."
            ),
            "events": [
                {"timestamp": e.timestamp, "level": e.level, "tag": e.tag, "kind": e.kind,
                 "mac_address": e.mac_address, "display_name": e.display_name,
                 "package_name": e.package_name, "association_id": e.association_id,
                 "detail": e.detail, "confidence": pairing_confidence, "corroboration": pairing_corroboration,
                 **_capture_tag(e.capture_id),
                 "source": {"section": e.source_section, "line_start": e.source_line_start, "line_end": e.source_line_end}}
                for e in pairing_events
            ],
        }
        # The service's own current-state association snapshot -- a
        # materially stronger source than the log-line events above, since
        # it's not reconstructed from a sequence of messages but reported
        # directly by CDM at the moment the bugreport was taken. Real gap
        # found live: this "DUMP OF SERVICE companiondevice" section was
        # being extracted from the bugreport but never had a parser wired
        # to it at all, so "is this device currently paired/connected" had
        # to be inferred from log anomalies even when the authoritative
        # answer was sitting a few hundred lines away the whole time.
        associations = session.exec(
            select(CompanionDeviceAssociationRow).where(CompanionDeviceAssociationRow.capture_id.in_(sibling_capture_ids))
        ).all()
        if associations:
            bundle["device_wide_pairing_evidence"]["current_associations"] = [
                {"association_id": a.association_id, "mac_address": a.mac_address,
                 "display_name": a.display_name, "package_name": a.package_name,
                 "device_profile": a.device_profile, "revoked": a.revoked, "pending": a.pending,
                 "trusted": a.trusted, "time_approved": a.time_approved,
                 "last_time_connected": a.last_time_connected,
                 "currently_connected": a.currently_connected,
                 "confidence": pairing_confidence, "corroboration": pairing_corroboration,
                 **_capture_tag(a.capture_id),
                 "source": {"section": a.source_section, "line_start": a.source_line_start, "line_end": a.source_line_end}}
                for a in associations
            ]
        bt_rows = session.exec(
            select(BtHciSummaryRow).where(BtHciSummaryRow.capture_id.in_(sibling_capture_ids))
        ).all()
        if bt_rows:
            bundle["bt_hci_summary"] = []
            for bt_row in bt_rows:
                bt_events = session.exec(
                    select(BtHciEventRow).where(BtHciEventRow.capture_id == bt_row.capture_id)
                ).all()
                bundle["bt_hci_summary"].append({
                    "total_packets": bt_row.total_packets, "command_count": bt_row.command_count,
                    "event_count": bt_row.event_count, "first_timestamp": bt_row.first_timestamp,
                    "last_timestamp": bt_row.last_timestamp,
                    **_capture_tag(bt_row.capture_id),
                    "notable_events": [
                        {"timestamp": e.timestamp, "kind": e.kind, "status_name": e.status_name,
                         "reason_name": e.reason_name, "handle": e.handle}
                        for e in bt_events if e.kind == "disconnection_complete" or (e.status_code or 0) != 0
                    ],
                })
        pcap_rows = session.exec(
            select(PacketCaptureSummaryRow).where(PacketCaptureSummaryRow.capture_id.in_(sibling_capture_ids))
        ).all()
        if pcap_rows:
            bundle["packet_capture_summary"] = [
                {"format": p.format, "linktype_name": p.linktype_name,
                 "total_packets": p.total_packets, "first_timestamp": p.first_timestamp,
                 "last_timestamp": p.last_timestamp, **_capture_tag(p.capture_id),
                 "note": "Container-level metadata only -- see packet_analysis for protocol-level facts."}
                for p in pcap_rows
            ]
        pa_rows = session.exec(
            select(PacketAnalysisRow).where(PacketAnalysisRow.capture_id.in_(sibling_capture_ids))
        ).all()
        if pa_rows:
            bundle["packet_analysis"] = [
                {"backend": pa_row.backend, "link_layer": pa_row.link_layer,
                 "packets_analyzed": pa_row.packets_analyzed,
                 "retry_count": pa_row.retry_count, "retry_rate_pct": pa_row.retry_rate_pct,
                 "rssi_min_dbm": pa_row.rssi_min_dbm, "rssi_max_dbm": pa_row.rssi_max_dbm,
                 "rssi_avg_dbm": pa_row.rssi_avg_dbm, **_capture_tag(pa_row.capture_id),
                 "frame_type_breakdown": json.loads(pa_row.frame_type_breakdown_json),
                 "identity_signals": json.loads(pa_row.identity_signals_json),
                 "anomalies": json.loads(pa_row.anomalies_json),
                 "note": pa_row.note}
                for pa_row in pa_rows
            ]

    return bundle


def _run_llm(bundle: dict, system_prompt: str, provider: str | None) -> tuple[str | None, str | None]:
    user_prompt = (
        "Verified fact bundle (JSON):\n\n" + json.dumps(bundle, indent=2, default=str) +
        "\n\nWrite a diagnosis report answering the question above using only these facts."
    )
    try:
        llm = get_llm_client(provider)
        return llm.narrate(system_prompt, user_prompt), None
    except Exception as exc:  # noqa: BLE001 -- LLM narration is a convenience
        # layer on top of already-computed, independently verified facts.
        # A provider outage, quota error, or bad key should degrade to
        # "here are the facts, narration failed" -- never a 500 that hides
        # the verification work that already succeeded.
        return None, str(exc)


def diagnose(
    session: Session, capture_id: int, device_label: str, question: str,
    provider: str | None = None,
) -> dict:
    bundle = build_diagnosis_bundle(session, capture_id, device_label, question)
    report_text, llm_error = _run_llm(bundle, SYSTEM_PROMPT, provider)
    return {"bundle": bundle, "report": report_text, "llm_error": llm_error, "provider": provider}


INVESTIGATION_SYSTEM_PROMPT = SYSTEM_PROMPT + """
10. This bundle covers MULTIPLE captures, possibly from different physical
    devices, grouped under one investigation. The top-level "captures" array
    has one entry per capture, each tagged with "capture_id",
    "original_filename", and "device_label" -- always say which capture/
    device a fact came from, never merge facts from different captures into
    one unlabeled claim. When the question is about something happening
    "between" or "on one of" multiple devices, look across all entries and
    say which capture(s) actually show relevant evidence, rather than only
    reporting on the first one.
"""


def diagnose_investigation(
    session: Session, investigation_id: int, question: str, provider: str | None = None,
) -> dict:
    """Runs diagnosis across every capture linked to one investigation,
    merging each capture's independently-built bundle into one combined
    bundle before a single LLM call -- so a question naming "one of these
    N devices" can actually be answered by looking across all of them,
    instead of being scoped to whichever single capture happened to be
    selected.
    """
    from app.models.db_models import Capture, Device, InvestigationCaptureLink

    capture_rows = session.exec(
        select(Capture)
        .join(InvestigationCaptureLink, InvestigationCaptureLink.capture_id == Capture.id)
        .where(InvestigationCaptureLink.investigation_id == investigation_id)
    ).all()

    captures_bundle = []
    for capture in capture_rows:
        device = session.get(Device, capture.device_id)
        device_label = device.label if device else "unknown"
        per_capture = build_diagnosis_bundle(session, capture.id, device_label, question)
        captures_bundle.append({
            "capture_id": capture.id,
            "original_filename": capture.original_filename,
            "device_label": device_label,
            **per_capture,
        })

    bundle = {"question": question, "captures": captures_bundle}
    report_text, llm_error = _run_llm(bundle, INVESTIGATION_SYSTEM_PROMPT, provider)
    return {"bundle": bundle, "report": report_text, "llm_error": llm_error, "provider": provider}
