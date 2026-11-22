"""End-to-end teacher -> student learning loop.

Steps:
  1. Ingest decompiled app.
  2. Teacher (frontier) scan            -> teacher findings + recall (reference ceiling).
  3. Student (open) baseline scan       -> recall_before.
  4. Teacher distills general lessons    (single pass, generality-guarded).
  5. Student rescan WITH lessons        -> recall_after.
  6. Report recall_before, recall_after, lift, lessons, findings, matches.

Clients can be injected (tests/offline). Otherwise they are built from config,
so switching models/providers is purely a config change.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .config import Config
from .ingest import ingest
from .lessons import LessonResult, distill_lessons
from .match import MatchResult, match_findings
from .models import build_client
from .models.base import ModelClient
from .scan import scan_codebase
from .schema import Finding, GroundTruthItem, load_ground_truth


@dataclass
class RunResult:
    app: str
    teacher_label: str
    student_label: str
    match_strategy: str
    teacher_findings: List[Finding]
    student_findings_before: List[Finding]
    student_findings_after: List[Finding]
    teacher_match: MatchResult
    match_before: MatchResult
    match_after: MatchResult
    lessons: LessonResult
    meta: Dict[str, Any] = field(default_factory=dict)
    # Per-repeat recall samples (len == eval.repeats). The headline recall is their
    # mean, so the reported lift is an average over student runs, not one noisy draw.
    recall_before_samples: List[float] = field(default_factory=list)
    recall_after_samples: List[float] = field(default_factory=list)

    @staticmethod
    def _mean(xs: List[float]) -> float:
        return sum(xs) / len(xs) if xs else 0.0

    @property
    def recall_before(self) -> float:
        return self._mean(self.recall_before_samples) if self.recall_before_samples else self.match_before.recall

    @property
    def recall_after(self) -> float:
        return self._mean(self.recall_after_samples) if self.recall_after_samples else self.match_after.recall

    @property
    def recall_lift(self) -> float:
        return self.recall_after - self.recall_before

    def to_dict(self) -> Dict[str, Any]:
        return {
            "app": self.app,
            "models": {"teacher": self.teacher_label, "student": self.student_label},
            "match_strategy": self.match_strategy,
            "recall": {
                "teacher": round(self.teacher_match.recall, 4),
                "student_before": round(self.recall_before, 4),
                "student_after": round(self.recall_after, 4),
                "lift_absolute": round(self.recall_lift, 4),
                "lift_relative": (round(self.recall_lift / self.recall_before, 4)
                                  if self.recall_before else None),
                "repeats": len(self.recall_before_samples) or 1,
                "student_before_samples": [round(x, 4) for x in self.recall_before_samples],
                "student_after_samples": [round(x, 4) for x in self.recall_after_samples],
            },
            "matches": {
                "teacher": self.teacher_match.summary(),
                "student_before": self.match_before.summary(),
                "student_after": self.match_after.summary(),
            },
            "lessons": {
                "accepted": self.lessons.lessons,
                "rejected_as_instance_specific": self.lessons.rejected,
            },
            "counts": {
                "teacher_findings": len(self.teacher_findings),
                "student_findings_before": len(self.student_findings_before),
                "student_findings_after": len(self.student_findings_after),
            },
            "findings": {
                "teacher": [f.to_dict() for f in self.teacher_findings],
                "student_before": [f.to_dict() for f in self.student_findings_before],
                "student_after": [f.to_dict() for f in self.student_findings_after],
            },
            "meta": self.meta,
        }


def _match_kwargs(cfg: Config, judge: Optional[ModelClient]) -> Dict[str, Any]:
    return dict(
        strategy=cfg.get("match.strategy", "taxonomy"),
        fuzzy_threshold=float(cfg.get("match.fuzzy_threshold", 0.6)),
        require_location=bool(cfg.get("match.require_location", False)),
        judge=judge,
    )


def run_pipeline(cfg: Config, *,
                 teacher_client: Optional[ModelClient] = None,
                 student_client: Optional[ModelClient] = None,
                 logger=print) -> RunResult:
    log = logger or (lambda *_: None)
    retries = int(cfg.get("scan.retries", 3))
    backoff = float(cfg.get("scan.retry_backoff_seconds", 2.0))

    teacher = teacher_client or build_client(cfg.model_cfg("teacher"), retries=retries, backoff=backoff)
    student = student_client or build_client(cfg.model_cfg("student"), retries=retries, backoff=backoff)

    gt: List[GroundTruthItem] = load_ground_truth(cfg.get("ground_truth.path"))
    judge = teacher if cfg.get("match.strategy") == "llm_judge" else None
    mk = _match_kwargs(cfg, judge)

    log(f"[1/6] Ingesting {cfg.decompiled_path} ...")
    cb = ingest(cfg)
    log(f"      manifest={'yes' if cb.manifest else 'MISSING'}  files={len(cb.files)}  "
        f"chars={cb.total_chars}  gt_items={len(gt)}")
    max_chars = int(cfg.get("ingest.chunk.max_chars", 48000))

    t0 = time.time()
    log(f"[2/6] Teacher scan ({teacher.label}) ...")
    teacher_findings = scan_codebase(teacher, cb, max_chars=max_chars, role_label="teacher", logger=log)
    teacher_match = match_findings(teacher_findings, gt, **mk)
    log(f"      teacher findings={len(teacher_findings)}  recall={teacher_match.recall:.2%}")
    if not teacher_findings:
        log("      !! WARNING: teacher produced 0 findings. This usually means the teacher "
            "model was rate-limited / out of quota, not that the app is clean. No lessons "
            "can be distilled, so the recall lift from THIS run is NOT meaningful. "
            "Rotate the teacher model, wait for quota reset, or use a separate key.")

    log(f"[3/6] Distilling general lessons from teacher findings ...")
    lessons = distill_lessons(
        teacher, teacher_findings,
        max_lessons=int(cfg.get("lessons.max_lessons", 15)),
        enforce_generality=bool(cfg.get("lessons.enforce_generality", True)),
        logger=log,
    )
    log(f"      lessons accepted={lessons.n_accepted}  rejected={len(lessons.rejected)}")

    # Student baseline vs. lessoned, repeated `eval.repeats` times to average out
    # the small model's run-to-run noise. The only difference between the two
    # scans in each repeat is whether the lessons are injected.
    repeats = max(1, int(cfg.get("eval.repeats", 1)))
    before_samples: List[float] = []
    after_samples: List[float] = []
    student_before: List[Finding] = []
    student_after: List[Finding] = []
    match_before = match_after = None
    log(f"[4/6] Student scans ({student.label}) x{repeats} (baseline vs. +lessons) ...")
    for r in range(repeats):
        sb = scan_codebase(student, cb, max_chars=max_chars,
                           role_label=f"student_before#{r+1}", logger=(log if repeats == 1 else None))
        match_before = match_findings(sb, gt, **mk)
        before_samples.append(match_before.recall)
        student_before = sb

        sa = scan_codebase(student, cb, max_chars=max_chars, lessons=lessons.lessons,
                           role_label=f"student_after#{r+1}", logger=(log if repeats == 1 else None))
        match_after = match_findings(sa, gt, **mk)
        after_samples.append(match_after.recall)
        student_after = sa
        log(f"      repeat {r+1}/{repeats}: recall {match_before.recall:.2%} -> {match_after.recall:.2%}")

    mean_before = sum(before_samples) / len(before_samples)
    mean_after = sum(after_samples) / len(after_samples)
    lift = mean_after - mean_before
    log(f"[5/6] Aggregate over {repeats} run(s): "
        f"mean recall {mean_before:.2%} -> {mean_after:.2%}")
    log(f"[6/6] Done in {time.time() - t0:.1f}s. lift {lift:+.2%} "
        f"(before samples={[f'{x:.0%}' for x in before_samples]}, "
        f"after samples={[f'{x:.0%}' for x in after_samples]})")

    return RunResult(
        app=cfg.get("ground_truth.path", "app"),
        teacher_label=teacher.label,
        student_label=student.label,
        match_strategy=mk["strategy"],
        teacher_findings=teacher_findings,
        student_findings_before=student_before,
        student_findings_after=student_after,
        teacher_match=teacher_match,
        match_before=match_before,
        match_after=match_after,
        lessons=lessons,
        meta={
            "decompiled_path": cfg.decompiled_path,
            "files_scanned": len(cb.files),
            # A run is only meaningful if the teacher produced findings AND at least
            # one general lesson survived the guard. Otherwise the "lift" is an artifact.
            "valid_run": bool(teacher_findings) and bool(lessons.lessons),
            "teacher_empty": not teacher_findings,
            "repeats": repeats,
        },
        recall_before_samples=before_samples,
        recall_after_samples=after_samples,
    )
