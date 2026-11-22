"""Anthropic Claude provider (Messages API, REST)."""
from __future__ import annotations

import os
from typing import Any, Dict

from .base import ModelClient, ModelResponse
from .http import post_json

API = "https://api.anthropic.com/v1/messages"


class AnthropicClient(ModelClient):
    provider = "anthropic"
    env_key = "ANTHROPIC_API_KEY"

    def __init__(self, model: str, **kwargs: Any):
        super().__init__(model, **kwargs)
        self.api_key = os.environ.get(self.env_key)
        if not self.api_key:
            raise RuntimeError(f"{self.env_key} not set (needed for Anthropic provider).")

    def complete(self, system: str, user: str, *, json_mode: bool = True) -> ModelResponse:
        # Anthropic has no JSON mode flag; we nudge via the system prompt and the
        # caller's extract_json() tolerates prose around the JSON.
        sys_prompt = system
        if json_mode:
            sys_prompt += "\n\nRespond with ONLY valid JSON. No markdown, no prose."

        payload: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_output_tokens,
            "temperature": self.temperature,
            "system": sys_prompt,
            "messages": [{"role": "user", "content": user}],
        }
        data = post_json(
            API,
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            payload=payload,
            retries=int(self.extra.get("retries", 3)),
            backoff=float(self.extra.get("retry_backoff_seconds", 2.0)),
        )
        text = ""
        try:
            text = "".join(b.get("text", "") for b in data.get("content", []))
        except (KeyError, AttributeError):
            text = ""
        return ModelResponse(text=text, raw=data)
