"""Provider registry: provider name (string from config) -> ModelClient.

To add a model provider: implement a ModelClient subclass, import it here, and
add one line to _PROVIDERS. After that it is selectable purely from config.
"""
from __future__ import annotations

from typing import Any, Dict, Type

from .anthropic import AnthropicClient
from .base import ModelClient
from .gemini import GeminiClient
from .mock import MockClient
from .openai_compat import GroqClient, OpenAIClient

_PROVIDERS: Dict[str, Type[ModelClient]] = {
    "gemini": GeminiClient,
    "groq": GroqClient,
    "openai": OpenAIClient,
    "anthropic": AnthropicClient,
    "mock": MockClient,
}


def available_providers() -> list:
    return sorted(_PROVIDERS)


def build_client(model_cfg: Dict[str, Any], *, retries: int = 3, backoff: float = 2.0) -> ModelClient:
    provider = str(model_cfg.get("provider", "")).lower()
    if provider not in _PROVIDERS:
        raise ValueError(
            f"Unknown provider {provider!r}. Available: {available_providers()}. "
            f"Add a class in src/apkscan/models/ and register it in registry.py."
        )
    cls = _PROVIDERS[provider]
    return cls(
        model=model_cfg["model"],
        temperature=float(model_cfg.get("temperature", 0.0)),
        max_output_tokens=int(model_cfg.get("max_output_tokens", 8192)),
        retries=retries,
        retry_backoff_seconds=backoff,
    )
