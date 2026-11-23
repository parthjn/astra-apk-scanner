"""Multi-arm ablation experiment with repeats, mean, and spread.

Answers the reviewer asks directly:
  * >= 3 runs per arm with mean and spread  -> `repeats`
  * a control arm (generic checklist of similar length)
  * applying lessons to a second app with a baseline on that app -> run with
    `lessons_override` loaded from the first app's run.

Arms (configurable):
  baseline : student scans with NO extra guidance
  control  : student scans with a GENERIC security checklist (data/control_checklist.yaml)
  lessons  : student scans with the DISTILLED lessons (from the teacher, or loaded
             from another app's run via lessons_override)

Teacher scan + lesson distillation run ONCE; only the student scans repeat.
"""
from __future__ import annotations

import json
import os
import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

from .config import Config
from .ingest import ingest
from .lessons import LessonResult, distill_lessons
from .match import match_findings
from .models import build_client
from .models.base import ModelClient
from .scan import scan_codebase
from .schema import Finding, GroundTruthItem, load_ground_truth

DEFAULT_ARMS = ["baseline", "control", "lessons"]


@dataclass
class ArmResult:
    name: str
    recalls: List[float] = field(default_factory=list)
    precisions: List[float] = field(default_factory=list)
    matched_per_run: List[List[str]] = field(default_factory=list)
    n_findings: List[int] = field(default_factory=list)

    @property
    def mean_recall(self) -> float:
        return statistics.mean(self.recalls) if self.recalls else 0.0

    @property
    def stdev_recall(self) -> float:
        return statistics.pstdev(self.recalls) if len(self.recalls) > 1 else 0.0

    def summary(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "runs": len(self.recalls),
            "mean_recall": round(self.mean_recall, 4),
            "stdev_recall": round(self.stdev_recall, 4),
            "min_recall": round(min(self.recalls), 4) if self.recalls else None,
            "max_recall": round(max(self.recalls), 4) if self.recalls else None,
            "recall_samples": [round(x, 4) for x in self.recalls],
            "precision_samples": [round(x, 4) for x in self.precisions],
            "n_findings_per_run": self.n_findings,
            "matched_per_run": self.matched_per_run,
        }


@dataclass
class ExperimentResult:
    app: str
    teacher_label: str
    student_label: str
    match_strategy: str
    repeats: int
    arms: Dict[str, ArmResult]
    lessons: Optional[LessonResult]
    lessons_source: str
    control_checklist: List[str]
    teacher_recall: Optional[float]
    teacher_n_findings: int
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        base = self.arms.get("baseline")
        out: Dict[str, Any] = {
            "app": self.app,
            "models": {"teacher": self.teacher_label, "student": self.student_label},
            "match_strategy": self.match_strategy,
            "repeats": self.repeats,
            "lessons_source": self.lessons_source,
            "teacher": {"recall": self.teacher_recall, "n_findings": self.teacher_n_findings},
            "lessons": {
                "accepted": self.lessons.lessons if self.lessons else [],
                "rejected_as_instance_specific": self.lessons.rejected if self.lessons else [],
            },
            "control_checklist": self.control_checklist,
            "arms": {name: arm.summary() for name, arm in self.arms.items()},
            "deltas_vs_baseline": {},
            "meta": self.meta,
        }
        if base:
            for name, arm in self.arms.items():
                if name == "baseline":
                    continue
                out["deltas_vs_baseline"][name] = round(arm.mean_recall - base.mean_recall, 4)
        return out


def _load_control_checklist(cfg: Config) -> List[str]:
    path = cfg.get("experiment.control_checklist_path", "./data/control_checklist.yaml")
    if not path or not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    items = data.get("checklist", [])
    return [str(x).strip() for x in items if str(x).strip()]


def load_lessons_from_file(path: str) -> List[str]:
    """Load distilled lessons from a prior run's results.json or a lessons list file."""
    with open(path, "r", encoding="utf-8") as fh:
        if path.endswith((".yaml", ".yml")):
            data = yaml.safe_load(fh)
        else:
            data = json.load(fh)
    if isinstance(data, list):
        return [str(x).strip() for x in data if str(x).strip()]
    if isinstance(data, dict):
        # results.json shape: {"lessons": {"accepted": [...]}} or {"lessons": [...]}
        les = data.get("lessons")
        if isinstance(les, dict):
            return [str(x).strip() for x in les.get("accepted", []) if str(x).strip()]
        if isinstance(les, list):
            return [str(x).strip() for x in les if str(x).strip()]
    return []


def run_experiment(cfg: Config, *, arms: Optional[List[str]] = None,
                   repeats: Optional[int] = None,
                   teacher_client: Optional[ModelClient] = None,
                   student_client: Optional[ModelClient] = None,
                   lessons_override: Optional[List[str]] = None,
                   lessons_source: str = "distilled",
                   logger=print) -> ExperimentResult:
    log = logger or (lambda *_: None)
    arms = arms or list(cfg.get("experiment.arms", DEFAULT_ARMS))
    repeats = int(repeats if repeats is not None else cfg.get("eval.repeats", 3))
    retries = int(cfg.get("scan.retries", 3))
    backoff = float(cfg.get("scan.retry_backoff_seconds", 2.0))

    student = student_client or build_client(cfg.model_cfg("student"), retries=retries, backoff=backoff)
    gt: List[GroundTruthItem] = load_ground_truth(cfg.get("ground_truth.path"))
    mk = dict(strategy=cfg.get("match.strategy", "taxonomy"),
              fuzzy_threshold=float(cfg.get("match.fuzzy_threshold", 0.6)),
              require_location=bool(cfg.get("match.require_location", False)), judge=None)
    max_chars = int(cfg.get("ingest.chunk.max_chars", 48000))

    cb = ingest(cfg)
    log(f"Ingest: files={len(cb.files)} gt={len(gt)} | arms={arms} repeats={repeats}")

    # --- lessons (teacher scan + distill) only if the 'lessons' arm needs them ---
    lessons_result: Optional[LessonResult] = None
    distilled: List[str] = []
    teacher_recall = None
    teacher_n = 0
    if "lessons" in arms:
        if lessons_override is not None:
            distilled = list(lessons_override)
            lessons_result = LessonResult(lessons=distilled, rejected=[])
            log(f"Lessons: using {len(distilled)} loaded lesson(s) [source={lessons_source}]")
        else:
            teacher = teacher_client or build_client(cfg.model_cfg("teacher"), retries=retries, backoff=backoff)
            log(f"Teacher scan ({teacher.label}) for lesson distillation ...")
            tf = scan_codebase(teacher, cb, max_chars=max_chars, role_label="teacher", logger=None)
            tm = match_findings(tf, gt, **mk)
            teacher_recall, teacher_n = round(tm.recall, 4), len(tf)
            lessons_result = distill_lessons(
                teacher, tf, max_lessons=int(cfg.get("lessons.max_lessons", 15)),
                enforce_generality=bool(cfg.get("lessons.enforce_generality", True)), logger=log)
            distilled = lessons_result.lessons
            log(f"Lessons: accepted={len(distilled)} rejected={len(lessons_result.rejected)} "
                f"(teacher recall={teacher_recall:.2%})")

    control = _load_control_checklist(cfg) if "control" in arms else []
    guidance = {"baseline": None, "control": control or None, "lessons": distilled or None}

    results = {name: ArmResult(name=name) for name in arms}
    for r in range(repeats):
        for name in arms:
            sf = scan_codebase(student, cb, max_chars=max_chars, lessons=guidance.get(name),
                               role_label=f"{name}#{r+1}", logger=None)
            m = match_findings(sf, gt, **mk)
            arm = results[name]
            arm.recalls.append(m.recall)
            arm.precisions.append(m.precision)
            arm.matched_per_run.append(sorted(m.matched))
            arm.n_findings.append(len(sf))
        log(f"  repeat {r+1}/{repeats}: "
            + "  ".join(f"{name}={results[name].recalls[-1]:.2%}" for name in arms))

    for name in arms:
        a = results[name]
        log(f"ARM {name:9s}: mean={a.mean_recall:.2%}  sd={a.stdev_recall:.2%}  "
            f"samples={[f'{x:.0%}' for x in a.recalls]}")

    return ExperimentResult(
        app=cfg.get("ground_truth.path", "app"),
        teacher_label=(teacher_client.label if teacher_client else cfg.get("models.teacher.model", "?")),
        student_label=student.label,
        match_strategy=mk["strategy"],
        repeats=repeats,
        arms=results,
        lessons=lessons_result,
        lessons_source=lessons_source,
        control_checklist=control,
        teacher_recall=teacher_recall,
        teacher_n_findings=teacher_n,
        meta={"decompiled_path": cfg.decompiled_path, "files_scanned": len(cb.files)},
    )


def write_experiment_report(result: ExperimentResult, out_dir: str) -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    run_dir = os.path.join(out_dir, f"experiment-{stamp}")
    os.makedirs(run_dir, exist_ok=True)
    with open(os.path.join(run_dir, "experiment.json"), "w", encoding="utf-8") as fh:
        json.dump(result.to_dict(), fh, indent=2)

    base = result.arms.get("baseline")
    md = [f"# Ablation experiment — {stamp}\n",
          f"- App ground truth: `{result.app}`",
          f"- Teacher: `{result.teacher_label}`  Student: `{result.student_label}`",
          f"- Match: `{result.match_strategy}`  Repeats/arm: **{result.repeats}**",
          f"- Lessons source: `{result.lessons_source}`\n",
          "## Recall by arm (mean ± sd over repeats)\n",
          "| Arm | Mean recall | Std dev | Min | Max | Δ vs baseline | Samples |",
          "|---|---|---|---|---|---|---|"]
    for name, arm in result.arms.items():
        delta = ("—" if name == "baseline" or not base
                 else f"{arm.mean_recall - base.mean_recall:+.1%}")
        samples = ", ".join(f"{x:.0%}" for x in arm.recalls)
        md.append(f"| {name} | {arm.mean_recall:.1%} | {arm.stdev_recall:.1%} | "
                  f"{min(arm.recalls):.0%} | {max(arm.recalls):.0%} | {delta} | {samples} |")
    md.append("")
    if result.teacher_recall is not None:
        md.append(f"_Teacher recall (reference): {result.teacher_recall:.1%} "
                  f"from {result.teacher_n_findings} findings._\n")
    if result.lessons:
        md.append("## Distilled lessons (accepted)\n")
        for i, l in enumerate(result.lessons.lessons, 1):
            md.append(f"{i}. {l}")
        if result.lessons.rejected:
            md.append("\n### Rejected by generality guard (instance-specific)\n")
            for l in result.lessons.rejected:
                md.append(f"- {l}")
        md.append("")
    if result.control_checklist:
        md.append("## Control checklist (generic, used in the `control` arm)\n")
        for i, c in enumerate(result.control_checklist, 1):
            md.append(f"{i}. {c}")
        md.append("")
    with open(os.path.join(run_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))
    return run_dir
