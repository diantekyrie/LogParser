"""The LLM is a reasoning/narration layer on top of parsed facts -- it never
sees raw bugreport text and never does retrieval. Every implementation of
this interface receives the same thing: a fully-assembled bundle of
structured, source-cited facts, and returns prose that organizes them. It is
not allowed to be the source of any factual claim; that's why callers pass
it already-verified data rather than a question to go investigate.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class LLMClient(ABC):
    @abstractmethod
    def narrate(self, system_prompt: str, user_prompt: str) -> str:
        """Return prose. Implementations must not fabricate facts not
        present in user_prompt -- the system prompt used throughout this
        app instructs that explicitly, but a real integration should also
        be validated against that constraint (e.g. via eval)."""
        raise NotImplementedError
