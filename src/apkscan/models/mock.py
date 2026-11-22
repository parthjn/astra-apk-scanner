"""Deterministic mock client for tests and offline demos (no API key needed).

Lets us exercise the ENTIRE pipeline — scan, lesson distillation, matching,
recall-lift measurement — without any network or credits. A responder callable
receives (system, user) and returns the raw text the "model" would produce, so
tests can simulate a weak student that improves once lessons appear in the prompt.
"""
from __future__ import annotations

from typing import Any, Callable, List, Optional

from .base import ModelClient, ModelResponse

Responder = Callable[[str, str], str]


class MockClient(ModelClient):
    provider = "mock"

    def __init__(self, model: str = "mock-1", *,
                 responder: Optional[Responder] = None,
                 script: Optional[List[str]] = None, **kwargs: Any):
        super().__init__(model, **kwargs)
        self._responder = responder
        self._script = list(script) if script else None
        self.calls: List[tuple] = []

    def complete(self, system: str, user: str, *, json_mode: bool = True) -> ModelResponse:
        self.calls.append((system, user))
        if self._responder is not None:
            return ModelResponse(text=self._responder(system, user), raw={"mock": True})
        if self._script:
            return ModelResponse(text=self._script.pop(0), raw={"mock": True})
        return ModelResponse(text="[]", raw={"mock": True})
