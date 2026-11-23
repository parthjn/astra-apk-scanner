"""Teacher -> general lessons, in a single pass, with a generality guard.

The assignment requires lessons to be GENERAL rules, never instance-specific.
We enforce that programmatically: after the teacher produces lessons, we reject
(and log) any lesson that leaks a concrete file name, line number, or a specific
class/identifier taken from the findings. This is both a correctness guard and a
piece of honest measurement — we can report how many lessons were rejected.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

from . import prompts
from .jsonutil import extract_string_list
from .models.base import ModelClient
from .schema import Finding, findings_to_json

# Instance-specific leakage signals. We deliberately DO allow general security
# vocabulary that makes a lesson actionable: API/method names (getParcelableExtra,
# handler.proceed()), generic framework files (AndroidManifest.xml, strings.xml),
# and prose like "SSL/TLS". We reject only things that are specific to THIS app:
# an explicit line number, an app source file (*.java/*.kt/*.smali), or an
# app class/package identifier taken from the findings (see _banned_tokens).
_LINE_REF = re.compile(r"\bline\s*\d+\b", re.I)
_SRC_FILE_REF = re.compile(r"\b[\w$]+\.(?:java|kt|smali)\b", re.I)


@dataclass
class LessonResult:
    lessons: List[str]
    rejected: List[str]

    @property
    def n_accepted(self) -> int:
        return len(self.lessons)


def _looks_instance_specific(lesson: str, banned_tokens: set) -> bool:
    if _LINE_REF.search(lesson) or _SRC_FILE_REF.search(lesson):
        return True
    low = lesson.lower()
    for tok in banned_tokens:
        # whole-word match of a specific identifier/class/package from the findings
        if tok and len(tok) >= 4 and re.search(rf"\b{re.escape(tok)}\b", low):
            return True
    return False


def _banned_tokens(findings: List[Finding]) -> set:
    """Concrete, app-specific identifiers that must NOT appear in a general lesson:
    the app package, its class names, and app source-file basenames."""
    toks = set()
    for f in findings:
        if f.component:
            comp = f.component.lower()
            toks.add(comp)                        # e.g. com.insecureshop.loginactivity
            toks.add(comp.rsplit(".", 1)[-1])     # simple class name
            if "." in comp:
                toks.add(comp.rsplit(".", 1)[0])  # package prefix com.insecureshop
        if f.file:
            base = f.file.rsplit("/", 1)[-1].rsplit(".", 1)[0]
            toks.add(base.lower())
    # Don't ban generic Android words / framework file names, even when a finding
    # cites them as a location — they appear in EVERY app, so a lesson mentioning
    # e.g. "AndroidManifest.xml" or "strings.xml" is still general, not app-specific.
    toks -= {
        "main", "login", "result", "chooser", "web", "webview", "activity",
        "provider", "receiver", "service", "application",
        "androidmanifest", "manifest", "strings", "arrays", "styles", "colors",
        "dimens", "themes", "values", "buildconfig", "resources", "drawable",
        "layout", "menu", "mipmap", "string", "array",
    }
    return toks


def distill_lessons(teacher: ModelClient, findings: List[Finding], *,
                    max_lessons: int = 15, enforce_generality: bool = True,
                    logger=None) -> LessonResult:
    if not findings:
        return LessonResult(lessons=[], rejected=[])

    system = prompts.build_distill_system(max_lessons)
    user = prompts.DISTILL_USER.format(findings_json=findings_to_json(findings))
    resp = teacher.complete(system, user, json_mode=True)
    raw_lessons = extract_string_list(resp.text, key_hint="lessons")[:max_lessons]

    if not enforce_generality:
        return LessonResult(lessons=raw_lessons, rejected=[])

    banned = _banned_tokens(findings)
    accepted, rejected = [], []
    for l in raw_lessons:
        if _looks_instance_specific(l, banned):
            rejected.append(l)
        else:
            accepted.append(l)
    if logger and rejected:
        logger(f"  dropped {len(rejected)} instance-specific lesson(s) by the generality guard")
    return LessonResult(lessons=accepted, rejected=rejected)
