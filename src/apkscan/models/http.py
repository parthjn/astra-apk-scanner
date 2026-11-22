"""Tiny HTTP helper with retry/backoff, shared by REST providers."""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

import requests


class ModelHTTPError(RuntimeError):
    pass


def post_json(url: str, *, headers: Dict[str, str], payload: Dict[str, Any],
              params: Optional[Dict[str, str]] = None,
              retries: int = 3, backoff: float = 2.0, timeout: int = 120) -> Dict[str, Any]:
    last_err: Optional[Exception] = None
    for attempt in range(retries):
        try:
            resp = requests.post(url, headers=headers, params=params, json=payload, timeout=timeout)
            if resp.status_code == 429 or resp.status_code >= 500:
                # transient: honor Retry-After when present, else exp backoff
                wait = float(resp.headers.get("Retry-After", backoff * (2 ** attempt)))
                time.sleep(min(wait, 60))
                last_err = ModelHTTPError(f"{resp.status_code}: {resp.text[:300]}")
                continue
            if resp.status_code >= 400:
                raise ModelHTTPError(f"{resp.status_code}: {resp.text[:500]}")
            return resp.json()
        except (requests.RequestException, ModelHTTPError) as e:
            last_err = e
            time.sleep(backoff * (2 ** attempt))
    raise ModelHTTPError(f"HTTP failed after {retries} attempts: {last_err}")
