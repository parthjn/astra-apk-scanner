"""Run a model over the ingested codebase and collect structured findings."""
from __future__ import annotations

from typing import List, Optional

from . import prompts
from .ingest import CodeBase, build_chunks
from .jsonutil import extract_findings_list
from .models.base import ModelClient
from .schema import Finding


def _dedupe(findings: List[Finding]) -> List[Finding]:
    """Collapse near-duplicate findings (same category + same file+component)."""
    seen = {}
    for f in findings:
        key = (f.category or f.vuln_type.lower(), f.file, f.component)
        if key not in seen or f.confidence > seen[key].confidence:
            seen[key] = f
    return list(seen.values())


def scan_codebase(client: ModelClient, cb: CodeBase, *, max_chars: int,
                  lessons: Optional[List[str]] = None,
                  role_label: Optional[str] = None,
                  logger=None) -> List[Finding]:
    """Scan the whole codebase, chunk by chunk, and return deduped findings.

    `lessons`, when provided, are injected into every chunk prompt — this is the
    only difference between the student's baseline scan and its post-lesson scan.
    """
    chunks = build_chunks(cb, max_chars=max_chars)
    system = prompts.build_scan_system()
    all_findings: List[Finding] = []

    for ch in chunks:
        user = prompts.build_scan_user(ch.text, ch.index + 1, len(chunks), lessons)
        try:
            resp = client.complete(system, user, json_mode=True)
            raw_items = extract_findings_list(resp.text)
        except Exception as e:  # noqa: BLE001 - one bad chunk must not kill the run
            if logger:
                logger(f"  ! chunk {ch.index + 1}/{len(chunks)} failed: {e}")
            continue
        for item in raw_items:
            all_findings.append(Finding.from_model_dict(item, source_model=role_label or client.label))
        if logger:
            logger(f"  chunk {ch.index + 1}/{len(chunks)}: {len(raw_items)} findings "
                   f"({', '.join(ch.files[:2])}{'...' if len(ch.files) > 2 else ''})")

    return _dedupe(all_findings)
