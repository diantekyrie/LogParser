"""OpenAI-backed LLMClient, activated when OPENAI_API_KEY is set (and no
ANTHROPIC_API_KEY takes precedence -- see app/llm/__init__.py). Same
contract as AnthropicClient: narrates an already-verified fact bundle, adds
no facts of its own.
"""
from __future__ import annotations

import os

from app.llm.interface import LLMClient

DEFAULT_MODEL = "gpt-4.1"


class OpenAIClient(LLMClient):
    def __init__(self, model: str = DEFAULT_MODEL):
        import openai  # imported lazily so the stub/anthropic paths have no hard dependency

        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is not set")
        self._client = openai.OpenAI(api_key=api_key)
        self._model = os.environ.get("OPENAI_MODEL", model)

    def narrate(self, system_prompt: str, user_prompt: str) -> str:
        response = self._client.chat.completions.create(
            model=self._model,
            max_tokens=2048,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        return response.choices[0].message.content or ""
