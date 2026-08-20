"""The verification pass: given a natural-language question that names
specific apps, independently pull each named app's own parsed state before
any narrative gets constructed. This is what would have caught "YouTube
Music didn't pause" being false -- its own MediaSession history showed it
had already paused for an unrelated reason before the incident window.

The user's framing of a question is never treated as a fact. Every package
name mentioned gets its own state pulled and reported, whether or not it
supports the story the question implies.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from sqlmodel import Session, select

from app.models.db_models import (
    Capture,
    CrashEventRow,
    FocusEventRow,
    FocusStackEntryRow,
    ForegroundServiceRow,
    FreezeSummaryRow,
    MediaSessionRow,
    PackageFactRow,
)

PACKAGE_ID_RE = re.compile(r"\b([a-z][a-z0-9_]*(?:\.[a-z0-9_]+){2,})\b", re.IGNORECASE)

# Segments too generic to count as an app-identifying word on their own
# (they appear in hundreds of packages, and short common English words like
# "and"/"the" can otherwise substring-match into "android").
GENERIC_SEGMENTS = {
    "com", "org", "net", "android", "google", "apps", "app", "service",
    "services", "android_", "gms", "google_apps",
}
STOPWORDS = {
    "the", "and", "for", "was", "did", "has", "have", "not", "with", "that",
    "this", "when", "what", "why", "how", "app", "apps",
}


@dataclass
class EntityVerification:
    package: str
    matched_how: str                          # "literal_package_id" | "name_fragment_match"
    is_top_of_focus_stack: bool
    media_session_active: bool | None
    media_session_playback_state: str | None
    media_session_position_ms: int | None
    media_session_source: dict | None
    latest_focus_event: dict | None            # {"event_type", "timestamp", "detail", "source"}
    target_sdk: int | None
    target_sdk_source: dict | None
    crash_events: list[dict]           # Java FATAL EXCEPTION crashes attributed to this package
    freeze_count: int
    unfreeze_count: int
    corroborating_fact_count: int


def _known_packages(session: Session, capture_id: int) -> list[str]:
    rows = session.exec(
        select(PackageFactRow.package).where(PackageFactRow.capture_id == capture_id)
    ).all()
    return list(rows)


def extract_candidate_packages(question: str, known_packages: list[str]) -> list[str]:
    found: set[str] = set()

    for m in PACKAGE_ID_RE.finditer(question):
        candidate = m.group(1).lower()
        if candidate in known_packages:
            found.add(candidate)

    # Fallback: fuzzy match on brand words, e.g. "YouTube Music" -> a package
    # whose dotted segments exactly equal "youtube" and "music". Matching is
    # exact-segment only (not substring) and skips generic segments/stop
    # words -- substring matching let three-letter words like "and" falsely
    # match inside "android", which is exactly the kind of unverified
    # inference this pass exists to avoid.
    words = {
        w.lower() for w in re.findall(r"[A-Za-z]+", question)
        if len(w) > 2 and w.lower() not in STOPWORDS
    }
    for pkg in known_packages:
        segments = {s for s in pkg.lower().split(".") if s not in GENERIC_SEGMENTS}
        hits = words & segments
        if len(hits) >= 2:
            found.add(pkg)

    return sorted(found)


def verify_entity(session: Session, capture_id: int, package: str, matched_how: str) -> EntityVerification:
    focus_top = session.exec(
        select(FocusStackEntryRow).where(
            FocusStackEntryRow.capture_id == capture_id,
            FocusStackEntryRow.package == package,
            FocusStackEntryRow.is_top_of_stack == True,  # noqa: E712
        )
    ).first()

    media = session.exec(
        select(MediaSessionRow).where(
            MediaSessionRow.capture_id == capture_id, MediaSessionRow.package == package
        )
    ).first()

    latest_event = session.exec(
        select(FocusEventRow)
        .where(FocusEventRow.capture_id == capture_id, FocusEventRow.package == package)
        .order_by(FocusEventRow.id.desc())
    ).first()

    pkg_fact = session.exec(
        select(PackageFactRow).where(
            PackageFactRow.capture_id == capture_id, PackageFactRow.package == package
        )
    ).first()

    crash_rows = session.exec(
        select(CrashEventRow).where(
            CrashEventRow.capture_id == capture_id, CrashEventRow.package == package
        )
    ).all()

    freeze_summary = session.exec(
        select(FreezeSummaryRow).where(
            FreezeSummaryRow.capture_id == capture_id, FreezeSummaryRow.package == package
        )
    ).first()

    corroborating = sum(x is not None for x in (focus_top, media, latest_event, pkg_fact))
    corroborating += len(crash_rows)
    if freeze_summary is not None:
        corroborating += 1

    return EntityVerification(
        package=package,
        matched_how=matched_how,
        is_top_of_focus_stack=focus_top is not None,
        media_session_active=media.active if media else None,
        media_session_playback_state=media.playback_state if media else None,
        media_session_position_ms=media.position_ms if media else None,
        media_session_source=(
            {"section": media.source_section, "line_start": media.source_line_start, "line_end": media.source_line_end}
            if media else None
        ),
        latest_focus_event=(
            {"event_type": latest_event.event_type, "timestamp": latest_event.timestamp, "detail": latest_event.detail,
             "source": {"section": latest_event.source_section, "line_start": latest_event.source_line_start, "line_end": latest_event.source_line_end}}
            if latest_event else None
        ),
        target_sdk=pkg_fact.target_sdk if pkg_fact else None,
        target_sdk_source=(
            {"section": pkg_fact.source_section, "line_start": pkg_fact.source_line_start, "line_end": pkg_fact.source_line_end}
            if pkg_fact else None
        ),
        crash_events=[
            {
                "timestamp": c.timestamp, "exception_class": c.exception_class, "message": c.message,
                "source": {"section": c.source_section, "line_start": c.source_line_start, "line_end": c.source_line_end},
            }
            for c in crash_rows
        ],
        freeze_count=freeze_summary.freeze_count if freeze_summary else 0,
        unfreeze_count=freeze_summary.unfreeze_count if freeze_summary else 0,
        corroborating_fact_count=corroborating,
    )


def verify_question_entities(session: Session, capture_id: int, question: str) -> list[EntityVerification]:
    known = _known_packages(session, capture_id)

    literal_hits = {m.group(1).lower() for m in PACKAGE_ID_RE.finditer(question)} & set(known)
    fragment_hits = set(extract_candidate_packages(question, known)) - literal_hits

    results = [verify_entity(session, capture_id, pkg, "literal_package_id") for pkg in sorted(literal_hits)]
    results += [verify_entity(session, capture_id, pkg, "name_fragment_match") for pkg in sorted(fragment_hits)]
    return results
