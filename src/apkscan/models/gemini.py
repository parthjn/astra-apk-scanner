"""Google Gemini provider (Google AI Studio REST API)."""
from __future__ import annotations

import os
from typing import Any, Dict

from .base import ModelClient, ModelResponse
from .http import post_json

API = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


class GeminiClient(ModelClient):
    provider = "gemini"
    env_key = "GOOGLE_API_KEY"

    def __init__(self, model: str, **kwargs: Any):
        super().__init__(model, **kwargs)
        self.api_key = os.environ.get(self.env_key)
        if not self.api_key:
            raise RuntimeError(f"{self.env_key} not set (needed for Gemini provider).")

    def complete(self, system: str, user: str, *, json_mode: bool = True) -> ModelResponse:
        gen_cfg: Dict[str, Any] = {
            "temperature": self.temperature,
            "maxOutputTokens": self.max_output_tokens,
        }
        if json_mode:
            gen_cfg["responseMimeType"] = "application/json"

        payload = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": gen_cfg,
        }
        data = post_json(
            API.format(model=self.model),
            headers={"Content-Type": "application/json"},
            params={"key": self.api_key},
            payload=payload,
            retries=int(self.extra.get("retries", 3)),
            backoff=float(self.extra.get("retry_backoff_seconds", 2.0)),
        )
        text = ""
        try:
            parts = data["candidates"][0]["content"]["parts"]
            text = "".join(p.get("text", "") for p in parts)
        except (KeyError, IndexError):
            text = ""
        return ModelResponse(text=text, raw=data)
