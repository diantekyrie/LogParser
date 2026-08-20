"""Client selection: ANTHROPIC_API_KEY takes precedence if set, then
OPENAI_API_KEY, otherwise fall back to the deterministic stub. Nothing else
in the codebase should import a concrete client directly -- go through
get_llm_client() so swapping providers is invisible to callers.
"""
from __future__ import annotations

import os

from app.llm.interface import LLMClient


def get_llm_client() -> LLMClient:
    if os.environ.get("ANTHROPIC_API_KEY"):
        from app.llm.anthropic_client import AnthropicClient
        return AnthropicClient()
    if os.environ.get("OPENAI_API_KEY"):
        from app.llm.openai_client import OpenAIClient
        return OpenAIClient()
    from app.llm.stub_client import StubLLMClient
    return StubLLMClient()
