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
    paths: List[str] = getattr(args, "config", None) or [DEFAULT_CONFIG]
    cfg = load_config(paths)
    overrides = getattr(args, "set", None)
    if overrides:
        cfg = apply_dotted_overrides(cfg, overrides)
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


def cmd_experiment(args) -> int:
    from .experiment import load_lessons_from_file, run_experiment, write_experiment_report
    cfg = _load(args)
    arms = [a.strip() for a in args.arms.split(",")] if args.arms else None
    override = None
    source = "distilled"
    if args.lessons_from:
        override = load_lessons_from_file(args.lessons_from)
        source = f"loaded:{os.path.basename(args.lessons_from)}"
        print(f"Loaded {len(override)} lesson(s) from {args.lessons_from}")
    result = run_experiment(cfg, arms=arms, repeats=args.repeats,
                            lessons_override=override, lessons_source=source, logger=print)
    run_dir = write_experiment_report(result, cfg.get("output.dir", "runs"))
    print(f"\nArtifacts: {run_dir}")
    print(json.dumps({k: v["mean_recall"] for k, v in result.to_dict()["arms"].items()}, indent=2))
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
    # Common options live on a parent parser so `-c`/`--set` work BOTH before and
    # after the subcommand (e.g. `apkscan experiment --set app.decompiled_path=...`).
    common = argparse.ArgumentParser(add_help=False)
    # SUPPRESS defaults so a value given before the subcommand is not clobbered by
    # the subparser's default when the flag is absent after the subcommand.
    common.add_argument("-c", "--config", action="append", default=argparse.SUPPRESS,
                        help="config YAML (repeatable; later wins)")
    common.add_argument("--set", action="append", dest="set", default=argparse.SUPPRESS,
                        help="dotted override, e.g. match.strategy=fuzzy")

    p = argparse.ArgumentParser(prog="apkscan", parents=[common],
                                description="Teacher-student LLM APK vulnerability scanner")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("providers", parents=[common], help="list registered model providers").set_defaults(func=cmd_providers)
    sub.add_parser("ingest", parents=[common], help="ingest decompiled app and print stats").set_defaults(func=cmd_ingest)

    sp = sub.add_parser("scan", parents=[common], help="run a single scan with one role")
    sp.add_argument("--role", choices=["teacher", "student"], default="teacher")
    sp.add_argument("--eval", action="store_true", help="also match against ground truth")
    sp.add_argument("--verbose", action="store_true")
    sp.set_defaults(func=cmd_scan)

    sub.add_parser("run", parents=[common], help="full teacher->student loop + report").set_defaults(func=cmd_run)

    ep = sub.add_parser("experiment", parents=[common], help="multi-arm ablation (baseline/control/lessons) with repeats")
    ep.add_argument("--repeats", type=int, default=None, help="runs per arm (default: eval.repeats)")
    ep.add_argument("--arms", default=None, help="comma list, e.g. baseline,control,lessons")
    ep.add_argument("--lessons-from", default=None,
                    help="path to a prior results.json/experiment.json to reuse its lessons "
                         "(e.g. apply app-1 lessons to app-2)")
    ep.set_defaults(func=cmd_experiment)
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
