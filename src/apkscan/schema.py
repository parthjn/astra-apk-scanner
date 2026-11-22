"""Core data structures: Finding, GroundTruthItem, and (de)serialization."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from . import taxonomy

SEVERITIES = ["critical", "high", "medium", "low", "info"]


@dataclass
class Finding:
    """One structured vulnerability finding from a model scan."""
    vuln_type: str                      # model's own label, e.g. "SSL error bypass"
    severity: str = "medium"
    evidence: str = ""                  # snippet or reasoning
    file: Optional[str] = None
    line: Optional[int] = None
    component: Optional[str] = None     # exported activity/provider/etc. if any
    confidence: float = 0.5
    category: Optional[str] = None      # canonical taxonomy category (filled in)
    source_model: Optional[str] = None  # which model/role produced it
    raw: Dict[str, Any] = field(default_factory=dict)

    def normalize(self) -> "Finding":
        """Fill canonical category + clamp severity. Idempotent.

        A model-supplied category is only trusted if it is a real taxonomy key;
        anything else (``"other"``, a hallucinated label, or empty) is
        re-derived from the finding text so matching stays reliable.
        """
        if not self.category or self.category not in taxonomy.TAXONOMY:
            self.category = taxonomy.classify(self.vuln_type, self.evidence, self.component or "")
        sev = (self.severity or "medium").strip().lower()
        self.severity = sev if sev in SEVERITIES else "medium"
        try:
            self.confidence = max(0.0, min(1.0, float(self.confidence)))
        except (TypeError, ValueError):
            self.confidence = 0.5
        return self

    @staticmethod
    def from_model_dict(d: Dict[str, Any], source_model: Optional[str] = None) -> "Finding":
        """Build from a (possibly messy) model JSON object, tolerating key aliases."""
        def pick(*keys, default=None):
            for k in keys:
                if k in d and d[k] not in (None, ""):
                    return d[k]
            return default

        line = pick("line", "line_number", "lineno")
        try:
            line = int(line) if line is not None else None
        except (TypeError, ValueError):
            line = None

        f = Finding(
            vuln_type=str(pick("vuln_type", "type", "title", "name", "vulnerability", default="unknown")),
            severity=str(pick("severity", "sev", default="medium")),
            evidence=str(pick("evidence", "description", "detail", "snippet", "reason", default="")),
            file=(str(pick("file", "path", "filename")) if pick("file", "path", "filename") else None),
            line=line,
            component=(str(pick("component", "class", "activity")) if pick("component", "class", "activity") else None),
            confidence=pick("confidence", "conf", default=0.5),
            category=pick("category", "canonical_category"),
            source_model=source_model,
            raw=d,
        )
        return f.normalize()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("raw", None)
        return d


@dataclass
class GroundTruthItem:
    id: str
    title: str
    category: str
    severity: str = "medium"
    location: Dict[str, Any] = field(default_factory=dict)


def load_ground_truth(path: str) -> List[GroundTruthItem]:
    import yaml  # local import keeps module import cheap
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    items = []
    for v in data.get("vulnerabilities", []):
        items.append(GroundTruthItem(
            id=str(v["id"]),
            title=str(v.get("title", v["id"])),
            category=str(v["category"]),
            severity=str(v.get("severity", "medium")),
            location=v.get("location", {}) or {},
        ))
    return items


def findings_to_json(findings: List[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2)
