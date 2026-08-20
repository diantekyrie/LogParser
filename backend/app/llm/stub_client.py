"""Deterministic stand-in for a real LLM call. No API key is wired in yet
(the user asked to stub this layer for the first build pass); this client
lets the rest of the pipeline -- fact assembly, verification, confidence
scoring, report structure -- be built and tested end-to-end without one.

It does not "reason" in any interesting sense: it just renders the
structured facts it's given into readable prose, deterministically, so the
same input always produces the same report. Swap in AnthropicClient once a
key is available; nothing else in the pipeline needs to change, since both
implement LLMClient.narrate(system_prompt, user_prompt).
"""
from __future__ import annotations

from app.llm.interface import LLMClient


class StubLLMClient(LLMClient):
    def narrate(self, system_prompt: str, user_prompt: str) -> str:
        return (
            "[stub LLM -- no ANTHROPIC_API_KEY configured, echoing the assembled facts "
            "verbatim instead of narrating them]\n\n" + user_prompt
        )
