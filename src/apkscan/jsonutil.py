"""Tolerant extraction of JSON from model output (handles code fences / prose)."""
from __future__ import annotations

import json
import re
from typing import Any, List

_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def _balanced_slice(text: str, open_ch: str, close_ch: str) -> str | None:
    start = text.find(open_ch)
    if start == -1:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        else:
            if c == '"':
                in_str = True
            elif c == open_ch:
                depth += 1
            elif c == close_ch:
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]
    return None


def extract_json(text: str) -> Any:
    """Parse JSON from a model response, tolerating ```fences``` and surrounding prose.

    Returns the parsed object, or raises ValueError if nothing parses.
    """
    if not text or not text.strip():
        raise ValueError("empty model response")

    candidates: List[str] = []
    for m in _FENCE.finditer(text):
        candidates.append(m.group(1).strip())
    candidates.append(text.strip())
    for ch_pair in (("[", "]"), ("{", "}")):
        sl = _balanced_slice(text, *ch_pair)
        if sl:
            candidates.append(sl)

    for c in candidates:
        try:
            return json.loads(c)
        except (json.JSONDecodeError, TypeError):
            continue
    raise ValueError(f"could not parse JSON from model output: {text[:200]!r}")


def extract_findings_list(text: str) -> List[dict]:
    """Return a list of finding dicts, accepting several container shapes."""
    obj = extract_json(text)
    if isinstance(obj, list):
        return [x for x in obj if isinstance(x, dict)]
    if isinstance(obj, dict):
        for key in ("findings", "vulnerabilities", "results", "issues"):
            if isinstance(obj.get(key), list):
                return [x for x in obj[key] if isinstance(x, dict)]
        # single finding object
        return [obj]
    return []


def extract_string_list(text: str, key_hint: str = "lessons") -> List[str]:
    obj = extract_json(text)
    if isinstance(obj, list):
        return [str(x).strip() for x in obj if str(x).strip()]
    if isinstance(obj, dict):
        for key in (key_hint, "lessons", "rules", "items"):
            if isinstance(obj.get(key), list):
                return [str(x).strip() for x in obj[key] if str(x).strip()]
    return []
