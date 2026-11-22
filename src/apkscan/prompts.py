"""Prompt templates. Kept app-agnostic: no InsecureShop-specific wording."""
from __future__ import annotations

from typing import List

from . import taxonomy

SCAN_SYSTEM = """You are a senior Android application security auditor performing \
STATIC analysis on decompiled app code (Java/Kotlin/smali) and resources \
(AndroidManifest.xml, XML).

Find concrete, exploitable security vulnerabilities. For each one, report where it \
is and why it is exploitable. Prefer precision: only report an issue you can point \
to in the provided code. Do not invent files or lines.

Return a JSON object: {"findings": [ ... ]} where each finding has:
  - "vuln_type":  short label of the weakness (e.g. "WebView loads arbitrary URL")
  - "category":   one of the allowed categories below, or "other"
  - "severity":   one of: critical, high, medium, low, info
  - "file":       file path as shown in the FILE header, or null
  - "line":       integer line number if identifiable, or null
  - "component":  the Android component involved (activity/provider/receiver), or null
  - "evidence":   the specific code/manifest snippet or precise reason it is exploitable
  - "confidence": 0.0-1.0

Allowed categories:
{categories}

Output ONLY the JSON object."""

SCAN_USER = """Scan the following decompiled app content for vulnerabilities.

{lessons_block}
--- BEGIN APP CONTENT (chunk {idx}/{total}) ---
{content}
--- END APP CONTENT ---

Return the JSON object of findings now."""

LESSONS_PREFIX = """Before you start, note these GENERAL LESSONS from an expert audit of \
OTHER apps. Process in two steps:
1. First do your OWN complete, independent analysis and report every vulnerability you \
find — exactly as you would without these lessons.
2. THEN use the lessons as an extra checklist to catch anything you missed, and add those.
The lessons only ADD coverage. Do NOT let them narrow your search, and do NOT drop a \
finding just because it isn't in the list. Verify each lesson against the actual code.

LESSONS:
{lessons}
"""

DISTILL_SYSTEM = """You are a principal security researcher writing a REUSABLE audit \
playbook for a junior auditor who will scan DIFFERENT apps.

Turn the given findings into GENERAL, TRANSFERABLE lessons. Each lesson is a pattern:
what the risky construct looks like, why it is dangerous, and what to search for.

HARD RULES:
- NEVER reference a specific file name, line number, class name, variable, or this app.
- A lesson must apply to ANY Android app, not just the one scanned.
- Good:  "Exported activities that forward a nested Intent extra to startActivity \
enable intent redirection; look for getParcelableExtra followed by startActivity."
- Bad:   "Fix line 42 of LoginActivity."

Return a JSON object: {"lessons": ["...", "..."]}. At most {max_lessons} lessons. \
Output ONLY the JSON object."""

DISTILL_USER = """Here are the findings from an expert scan (as JSON). Distill them into \
general lessons per the rules.

FINDINGS:
{findings_json}

Return the JSON object of lessons now."""

JUDGE_SYSTEM = """You decide whether a scanner FINDING refers to the same underlying \
vulnerability as a GROUND-TRUTH entry. Judge by the type of weakness and the \
component/behavior involved, not by exact wording. Return JSON: {"match": true|false}."""

JUDGE_USER = """GROUND TRUTH: {gt_title} (category: {gt_category}) — {gt_hint}

FINDING: {f_type} (category: {f_category}) — {f_evidence}

Do they describe the same vulnerability? Return {{"match": true}} or {{"match": false}}."""


def categories_block() -> str:
    return "\n".join(f"  - {c}" for c in taxonomy.canonical_categories())


def build_scan_system() -> str:
    # NB: use .replace, not .format — these templates embed literal JSON braces
    # (e.g. {"findings": ...}) that str.format would treat as fields.
    return SCAN_SYSTEM.replace("{categories}", categories_block())


def build_distill_system(max_lessons: int) -> str:
    return DISTILL_SYSTEM.replace("{max_lessons}", str(max_lessons))


def build_scan_user(content: str, idx: int, total: int, lessons: List[str] | None) -> str:
    lessons_block = ""
    if lessons:
        lessons_block = LESSONS_PREFIX.format(
            lessons="\n".join(f"- {l}" for l in lessons)
        )
    return SCAN_USER.format(lessons_block=lessons_block, idx=idx, total=total, content=content)
