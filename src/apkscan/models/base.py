"""Model provider interface. One method, so adding a provider is trivial."""
from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class ModelResponse:
    text: str
    raw: Dict[str, Any]


class ModelClient(abc.ABC):
    """Minimal interface every provider implements.

    Keeping this surface tiny is deliberate: the pipeline only needs
    "given a system + user prompt, return text (ideally JSON)". Adding GPT,
    Claude, Llama-on-Groq, etc. is one subclass + one registry line + config.
    """

    provider: str = "base"

    def __init__(self, model: str, *, temperature: float = 0.0,
                 max_output_tokens: int = 8192, **kwargs: Any):
        self.model = model
        self.temperature = temperature
        self.max_output_tokens = max_output_tokens
        self.extra = kwargs

    @abc.abstractmethod
    def complete(self, system: str, user: str, *, json_mode: bool = True) -> ModelResponse:
        """Return the model's completion for (system, user)."""

    @property
    def label(self) -> str:
        return f"{self.provider}:{self.model}"
