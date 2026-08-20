"""Client selection: use the real Anthropic client if ANTHROPIC_API_KEY is
set, otherwise fall back to the deterministic stub. Nothing else in the
codebase should import AnthropicClient/StubLLMClient directly -- go through
get_llm_client() so the swap is invisible to callers.
"""
from __future__ import annotations

import os

from app.llm.interface import LLMClient


def get_llm_client() -> LLMClient:
    if os.environ.get("ANTHROPIC_API_KEY"):
        from app.llm.anthropic_client import AnthropicClient
        return AnthropicClient()
    from app.llm.stub_client import StubLLMClient
    return StubLLMClient()
