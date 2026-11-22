"""Command-line entrypoint.

Examples
--------
  apkscan run                               # full loop with config/default.yaml
  apkscan run -c config/default.yaml -c config/myapp.yaml
  apkscan run --set models.student.provider=groq --set models.student.model=llama-3.3-70b-versatile
  apkscan ingest                            # just ingest + print stats
  apkscan scan --role teacher               # one scan, print findings JSON
  apkscan providers                         # list registered providers
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List

from .config import apply_dotted_overrides, load_config
from .models import available_providers

DEFAULT_CONFIG = os.path.join("config", "default.yaml")


def _load(args) -> "Config":  # noqa: F821
    paths: List[str] = args.config or [DEFAULT_CONFIG]
    cfg = load_config(paths)
    if getattr(args, "set", None):
        cfg = apply_dotted_overrides(cfg, args.set)
    return cfg


def _maybe_load_dotenv():
    """Load a local .env if present (no dependency on python-dotenv)."""
    if not os.path.exists(".env"):
        return
    with open(".env", "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


def cmd_providers(_args) -> int:
    print("Registered providers:", ", ".join(available_providers()))
    return 0


def cmd_ingest(args) -> int:
    from .ingest import build_chunks, ingest
    cfg = _load(args)
    cb = ingest(cfg)
    chunks = build_chunks(cb, int(cfg.get("ingest.chunk.max_chars", 48000)))
    print(json.dumps({
        "root": cb.root,
        "manifest": cb.manifest.path if cb.manifest else None,
        "files": len(cb.files),
        "total_chars": cb.total_chars,
        "chunks": len(chunks),
        "top_files": [f.path for f in cb.files[:10]],
    }, indent=2))
    return 0


def cmd_scan(args) -> int:
    from .ingest import ingest
    from .match import match_findings
    from .models import build_client
    from .scan import scan_codebase
    from .schema import findings_to_json, load_ground_truth
    cfg = _load(args)
    client = build_client(cfg.model_cfg(args.role))
    cb = ingest(cfg)
    findings = scan_codebase(client, cb, max_chars=int(cfg.get("ingest.chunk.max_chars", 48000)),
                             role_label=args.role, logger=(print if args.verbose else None))
    print(findings_to_json(findings))
    if args.eval:
        gt = load_ground_truth(cfg.get("ground_truth.path"))
        mr = match_findings(findings, gt, strategy=cfg.get("match.strategy", "taxonomy"),
                            fuzzy_threshold=float(cfg.get("match.fuzzy_threshold", 0.6)),
                            require_location=bool(cfg.get("match.require_location", False)))
        print("\n# eval:", json.dumps(mr.summary(), indent=2), file=sys.stderr)
    return 0


def cmd_run(args) -> int:
    from .pipeline import run_pipeline
    from .report import write_report
    cfg = _load(args)
    result = run_pipeline(cfg, logger=print)
    run_dir = write_report(result, cfg.get("output.dir", "runs"), cfg.get("ground_truth.path"))
    print(f"\nArtifacts written to: {run_dir}")
    print(json.dumps(result.to_dict()["recall"], indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="apkscan", description="Teacher-student LLM APK vulnerability scanner")
    p.add_argument("-c", "--config", action="append", help="config YAML (repeatable; later wins)")
    p.add_argument("--set", action="append", help="dotted override, e.g. match.strategy=fuzzy")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("providers", help="list registered model providers").set_defaults(func=cmd_providers)
    sub.add_parser("ingest", help="ingest decompiled app and print stats").set_defaults(func=cmd_ingest)

    sp = sub.add_parser("scan", help="run a single scan with one role")
    sp.add_argument("--role", choices=["teacher", "student"], default="teacher")
    sp.add_argument("--eval", action="store_true", help="also match against ground truth")
    sp.add_argument("--verbose", action="store_true")
    sp.set_defaults(func=cmd_scan)

    sub.add_parser("run", help="full teacher->student loop + report").set_defaults(func=cmd_run)
    return p


def main(argv=None) -> int:
    _maybe_load_dotenv()
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError, KeyError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
