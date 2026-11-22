"""OpenAI-compatible chat providers: OpenAI and Groq share the same wire format.

Groq's API is OpenAI-compatible, so one implementation covers both the frontier
(OpenAI) and the open-model student (Groq / Llama, Mixtral, gpt-oss, etc.).
"""
from __future__ import annotations

import os
from typing import Any, Dict

from .base import ModelClient, ModelResponse
from .http import post_json


class _OpenAICompatClient(ModelClient):
    base_url: str = ""      # subclass sets
    env_key: str = ""       # subclass sets

    def __init__(self, model: str, **kwargs: Any):
        super().__init__(model, **kwargs)
        self.api_key = os.environ.get(self.env_key)
        if not self.api_key:
            raise RuntimeError(f"{self.env_key} not set (needed for {self.provider} provider).")

    def complete(self, system: str, user: str, *, json_mode: bool = True) -> ModelResponse:
        payload: Dict[str, Any] = {
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_output_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        data = post_json(
            f"{self.base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            payload=payload,
            retries=int(self.extra.get("retries", 3)),
            backoff=float(self.extra.get("retry_backoff_seconds", 2.0)),
        )
        text = ""
        try:
            text = data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError):
            text = ""
        return ModelResponse(text=text, raw=data)


class OpenAIClient(_OpenAICompatClient):
    provider = "openai"
    base_url = "https://api.openai.com/v1"
    env_key = "OPENAI_API_KEY"


class GroqClient(_OpenAICompatClient):
    provider = "groq"
    base_url = "https://api.groq.com/openai/v1"
    env_key = "GROQ_API_KEY"
