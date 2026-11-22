"""Match model findings against ground-truth entries, and compute recall.

The match function is the most consequential design choice here, so it is small,
explicit, and swappable (config: match.strategy). See docs/writeup.md for the
rationale and the honest trade-offs.

Strategies
----------
taxonomy  (default): a finding matches a GT entry iff they normalize to the SAME
          canonical category (taxonomy.py). Deterministic, explainable, app-agnostic.
          Optionally also require location overlap (match.require_location).
fuzzy:    difflib similarity between the finding's label and the GT title >= threshold.
          A cheap catch-all when a category is missing.
llm_judge: ask a model whether finding == GT (semantic). Most flexible, but costs
          tokens and, if the judge is the teacher, biases eval — flagged in output.

Recall is measured over GROUND-TRUTH coverage: how many of the N GT entries were
hit by at least one finding. Each GT entry counts once (no double credit).
"""
from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .models.base import ModelClient
from .schema import Finding, GroundTruthItem


@dataclass
class MatchResult:
    strategy: str
    matched: Dict[str, Finding] = field(default_factory=dict)   # gt_id -> the finding that matched
    unmatched_gt: List[str] = field(default_factory=list)       # gt_ids with no match
    false_positives: List[Finding] = field(default_factory=list)  # findings matching no GT
    total_gt: int = 0

    @property
    def recall(self) -> float:
        return (len(self.matched) / self.total_gt) if self.total_gt else 0.0

    @property
    def precision(self) -> float:
        tp = len(self.matched)
        denom = tp + len(self.false_positives)
        return (tp / denom) if denom else 0.0

    def summary(self) -> Dict:
        return {
            "strategy": self.strategy,
            "recall": round(self.recall, 4),
            "precision": round(self.precision, 4),
            "matched_gt": sorted(self.matched),
            "unmatched_gt": sorted(self.unmatched_gt),
            "n_false_positives": len(self.false_positives),
            "total_gt": self.total_gt,
        }


def _norm(s: str) -> str:
    return " ".join((s or "").lower().split())


def _location_overlap(f: Finding, gt: GroundTruthItem) -> bool:
    """True if we cannot disprove they're the same location, or they clearly align.

    Decompiler path differences make strict file matching unreliable, so this is
    permissive: a component-name match counts; absence of location info is NOT
    treated as a mismatch.
    """
    comp = (gt.location or {}).get("component")
    if comp and f.component:
        return comp.lower() in f.component.lower() or f.component.lower() in comp.lower()
    if comp and f.file:
        return comp.lower() in f.file.lower()
    return True  # no component hint to contradict


def _match_taxonomy(findings, gt_items, require_location):
    matched: Dict[str, Finding] = {}
    used = set()
    for gt in gt_items:
        for i, f in enumerate(findings):
            if i in used:
                continue
            if f.category and f.category == gt.category and (not require_location or _location_overlap(f, gt)):
                matched[gt.id] = f
                used.add(i)
                break
    return matched, used


def _match_fuzzy(findings, gt_items, threshold):
    matched: Dict[str, Finding] = {}
    used = set()
    for gt in gt_items:
        best_i, best_score = None, 0.0
        for i, f in enumerate(findings):
            if i in used:
                continue
            score = difflib.SequenceMatcher(
                None, _norm(gt.title), _norm(f.vuln_type + " " + f.evidence[:120])
            ).ratio()
            if score > best_score:
                best_score, best_i = score, i
        if best_i is not None and best_score >= threshold:
            matched[gt.id] = findings[best_i]
            used.add(best_i)
    return matched, used


def _match_llm(findings, gt_items, judge: ModelClient):
    from . import prompts
    from .jsonutil import extract_json
    matched: Dict[str, Finding] = {}
    used = set()
    for gt in gt_items:
        # only consider plausible candidates to bound cost
        cands = [(i, f) for i, f in enumerate(findings)
                 if i not in used and (f.category == gt.category or
                 difflib.SequenceMatcher(None, _norm(gt.title), _norm(f.vuln_type)).ratio() > 0.4)]
        for i, f in cands:
            user = prompts.JUDGE_USER.format(
                gt_title=gt.title, gt_category=gt.category,
                gt_hint=(gt.location or {}).get("hint", ""),
                f_type=f.vuln_type, f_category=f.category or "none", f_evidence=f.evidence[:300])
            try:
                resp = judge.complete(prompts.JUDGE_SYSTEM, user, json_mode=True)
                verdict = extract_json(resp.text)
                if isinstance(verdict, dict) and verdict.get("match") is True:
                    matched[gt.id] = f
                    used.add(i)
                    break
            except Exception:  # noqa: BLE001
                continue
    return matched, used


def match_findings(findings: List[Finding], gt_items: List[GroundTruthItem], *,
                   strategy: str = "taxonomy", fuzzy_threshold: float = 0.6,
                   require_location: bool = False,
                   judge: Optional[ModelClient] = None) -> MatchResult:
    if strategy == "taxonomy":
        matched, used = _match_taxonomy(findings, gt_items, require_location)
    elif strategy == "fuzzy":
        matched, used = _match_fuzzy(findings, gt_items, fuzzy_threshold)
    elif strategy == "llm_judge":
        if judge is None:
            raise ValueError("strategy 'llm_judge' requires a judge model client")
        matched, used = _match_llm(findings, gt_items, judge)
    else:
        raise ValueError(f"unknown match strategy: {strategy}")

    unmatched = [gt.id for gt in gt_items if gt.id not in matched]
    fps = [f for i, f in enumerate(findings) if i not in used]
    return MatchResult(
        strategy=strategy, matched=matched, unmatched_gt=unmatched,
        false_positives=fps, total_gt=len(gt_items),
    )
