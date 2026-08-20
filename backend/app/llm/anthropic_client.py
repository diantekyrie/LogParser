"""Real LLM client, activated once ANTHROPIC_API_KEY is set. Not used by
default -- see app/llm/__init__.py for the selection logic.
"""
from __future__ import annotations

import os

from app.llm.interface import LLMClient

DEFAULT_MODEL = "claude-sonnet-5"


class AnthropicClient(LLMClient):
    def __init__(self, model: str = DEFAULT_MODEL):
        import anthropic  # imported lazily so the stub path has no hard dependency

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model

    def narrate(self, system_prompt: str, user_prompt: str) -> str:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=2048,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return "".join(block.text for block in response.content if block.type == "text")
