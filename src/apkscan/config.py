"""Config loading: YAML + shallow env expansion + dotted-key overrides."""
from __future__ import annotations

import copy
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import yaml


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


@dataclass
class Config:
    data: Dict[str, Any]

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return default
        return node

    # convenience accessors ------------------------------------------------
    @property
    def decompiled_path(self) -> str:
        return self.get("app.decompiled_path")

    @property
    def manifest_name(self) -> str:
        return self.get("app.manifest_name", "AndroidManifest.xml")

    @property
    def source_globs(self) -> List[str]:
        return self.get("app.source_globs", ["**/*.java", "**/*.kt", "**/*.smali", "**/*.xml"])

    def model_cfg(self, role: str) -> Dict[str, Any]:
        cfg = self.get(f"models.{role}")
        if not cfg:
            raise KeyError(f"No model config for role '{role}'")
        return cfg


def load_config(paths: Optional[List[str]] = None, overrides: Optional[Dict[str, Any]] = None) -> Config:
    """Load and merge one or more YAML config files (later wins), then overrides."""
    merged: Dict[str, Any] = {}
    for p in (paths or []):
        with open(p, "r", encoding="utf-8") as fh:
            merged = _deep_merge(merged, yaml.safe_load(fh) or {})
    if overrides:
        merged = _deep_merge(merged, overrides)
    return Config(merged)


def apply_dotted_overrides(cfg: Config, pairs: List[str]) -> Config:
    """Apply CLI overrides like ['models.student.provider=groq', 'match.strategy=fuzzy']."""
    override: Dict[str, Any] = {}
    for pair in pairs:
        if "=" not in pair:
            continue
        key, val = pair.split("=", 1)
        node = override
        parts = key.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = yaml.safe_load(val)  # parse ints/bools/etc.
    return Config(_deep_merge(cfg.data, override))
