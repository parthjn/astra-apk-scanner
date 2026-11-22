"""Write run artifacts: results.json + a human-readable Markdown report."""
from __future__ import annotations

import json
import os
import time
from typing import List

from .match import MatchResult
from .pipeline import RunResult


def _unmatched_table(gt_path: str, mr: MatchResult) -> str:
    from .schema import load_ground_truth
    gt = {g.id: g for g in load_ground_truth(gt_path)}
    rows = [f"  - {gid}: {gt[gid].title} ({gt[gid].category})" for gid in sorted(mr.unmatched_gt)]
    return "\n".join(rows) if rows else "  - (none)"


def write_report(result: RunResult, out_dir: str, gt_path: str) -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    run_dir = os.path.join(out_dir, f"run-{stamp}")
    os.makedirs(run_dir, exist_ok=True)

    with open(os.path.join(run_dir, "results.json"), "w", encoding="utf-8") as fh:
        json.dump(result.to_dict(), fh, indent=2)

    rb, ra = result.recall_before, result.recall_after
    lift = result.recall_lift
    rel = (lift / rb) if rb else None

    md = []
    md.append(f"# APK Scan Run — {stamp}\n")
    if not result.meta.get("valid_run", True):
        reason = ("teacher produced 0 findings (likely rate-limited / out of quota)"
                  if result.meta.get("teacher_empty") else "no general lessons survived the guard")
        md.append(f"> ⚠️ **INVALID RUN** — {reason}. The recall lift below is not meaningful; "
                  f"re-run with a working teacher model.\n")
    md.append(f"- **Teacher:** `{result.teacher_label}`")
    md.append(f"- **Student:** `{result.student_label}`")
    md.append(f"- **Match strategy:** `{result.match_strategy}`")
    md.append(f"- **Files scanned:** {result.meta.get('files_scanned')}\n")

    md.append("## Recall (headline)\n")
    md.append("| Model | Recall | Findings |")
    md.append("|---|---|---|")
    md.append(f"| Teacher (reference ceiling) | {result.teacher_match.recall:.1%} | {len(result.teacher_findings)} |")
    md.append(f"| Student — before lessons | {rb:.1%} | {len(result.student_findings_before)} |")
    md.append(f"| Student — after lessons | {ra:.1%} | {len(result.student_findings_after)} |")
    md.append("")
    md.append(f"**Recall lift: {lift:+.1%} absolute"
              + (f" ({rel:+.0%} relative)" if rel is not None else "") + "**\n")
    reps = result.meta.get("repeats", 1)
    if reps and reps > 1:
        bs = ", ".join(f"{x:.0%}" for x in result.recall_before_samples)
        as_ = ", ".join(f"{x:.0%}" for x in result.recall_after_samples)
        md.append(f"_Mean over {reps} runs. Baseline samples: [{bs}]. "
                  f"+lessons samples: [{as_}]._\n")

    md.append("## General lessons used\n")
    if result.lessons.lessons:
        for i, l in enumerate(result.lessons.lessons, 1):
            md.append(f"{i}. {l}")
    else:
        md.append("_(none)_")
    if result.lessons.rejected:
        md.append(f"\n_Dropped by generality guard (instance-specific): {len(result.lessons.rejected)}_")
    md.append("")

    md.append("## Ground-truth still missed after lessons\n")
    md.append(_unmatched_table(gt_path, result.match_after))
    md.append("")

    path = os.path.join(run_dir, "report.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))
    return run_dir
