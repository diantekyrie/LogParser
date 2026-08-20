"""Deterministic parsers for known-structured bugreport dumpsys sections.

These are ground truth. The LLM reasoning layer (see app/llm) only ever
reasons over what these parsers produce -- it never does semantic retrieval
over raw section text. Adding a new fact type means adding a parser here,
not a new prompt.
"""
from app.parsers.base import (
    ForegroundServiceFacts,
    FocusEvent,
    FocusStackEntry,
    MediaSessionFacts,
    PackageFacts,
    ParsedCapture,
    SourceRef,
)

WANTED_SECTIONS = {
    "audio", "package", "media_session", "activity", "system_log",
    "system_properties", "preamble", "wifi", "batterystats",
}

__all__ = [
    "ForegroundServiceFacts",
    "FocusEvent",
    "FocusStackEntry",
    "MediaSessionFacts",
    "PackageFacts",
    "ParsedCapture",
    "SourceRef",
    "WANTED_SECTIONS",
]
