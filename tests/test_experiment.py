"""Offline test of the multi-arm ablation experiment (no API key)."""
import json
from pathlib import Path

from apkscan.config import Config
from apkscan.experiment import run_experiment
from apkscan.models.mock import MockClient

REPO = Path(__file__).resolve().parents[1]

from test_pipeline import teacher_responder  # reuse teacher/distill mock


def _findings(cats):
    return json.dumps({"findings": [
        {"vuln_type": c, "category": c, "severity": "high", "evidence": c, "confidence": 0.9}
        for c in cats]})


def student_arm_responder(system, user):
    # distinguish arms by a phrase unique to each guidance block
    if "signature-level permission expose their data" in user:          # distilled lessons
        return _findings(["hardcoded_credentials", "insecure_logging", "ssl_validation_bypass",
                          "insecure_webview_settings", "webview_arbitrary_url_load"])
    if "Review every exported component" in user:                        # generic control checklist
        return _findings(["hardcoded_credentials", "insecure_logging", "ssl_validation_bypass"])
    return _findings(["hardcoded_credentials", "insecure_logging"])      # baseline


def test_experiment_arms_and_control(fake_app, gt_path):
    cfg = Config({
        "app": {"decompiled_path": fake_app, "source_globs": ["**/*.java", "**/*.xml"]},
        "ingest": {"chunk": {"max_chars": 48000}},
        "match": {"strategy": "taxonomy"},
        "ground_truth": {"path": gt_path},
        "experiment": {"arms": ["baseline", "control", "lessons"],
                       "control_checklist_path": str(REPO / "data" / "control_checklist.yaml")},
    })
    teacher = MockClient("mock-teacher", responder=teacher_responder)
    student = MockClient("mock-student", responder=student_arm_responder)
    res = run_experiment(cfg, repeats=3, teacher_client=teacher, student_client=student,
                         logger=lambda *_: None)

    assert set(res.arms) == {"baseline", "control", "lessons"}
    for arm in res.arms.values():
        assert len(arm.recalls) == 3
    # distilled lessons beat the generic checklist, which beats baseline
    assert res.arms["lessons"].mean_recall > res.arms["control"].mean_recall > res.arms["baseline"].mean_recall
    d = res.to_dict()
    assert d["deltas_vs_baseline"]["lessons"] > d["deltas_vs_baseline"]["control"] > 0
    assert len(res.control_checklist) >= 6          # generic checklist loaded
    assert len(res.lessons.lessons) >= 1            # distilled lessons present


def test_experiment_lessons_override(fake_app, gt_path):
    """Applying externally-loaded lessons (e.g. app-1 lessons on app-2) skips the teacher."""
    cfg = Config({
        "app": {"decompiled_path": fake_app, "source_globs": ["**/*.java", "**/*.xml"]},
        "ingest": {"chunk": {"max_chars": 48000}},
        "match": {"strategy": "taxonomy"},
        "ground_truth": {"path": gt_path},
        "experiment": {"control_checklist_path": str(REPO / "data" / "control_checklist.yaml")},
    })
    student = MockClient("mock-student", responder=student_arm_responder)
    # no teacher client passed; override supplies the lessons so teacher is never called
    res = run_experiment(cfg, arms=["baseline", "lessons"], repeats=2, student_client=student,
                         lessons_override=["Exported content providers without a signature-level "
                                           "permission expose their data to any app."],
                         lessons_source="loaded:app1", logger=lambda *_: None)
    assert res.teacher_recall is None            # teacher never ran
    assert res.arms["lessons"].mean_recall > res.arms["baseline"].mean_recall
    assert res.lessons_source == "loaded:app1"
