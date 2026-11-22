"""End-to-end loop with mock models — proves the measurement harness works and
that a recall lift is computed correctly, all offline (no API keys)."""
import json

from apkscan.config import Config
from apkscan.models.mock import MockClient
from apkscan.pipeline import run_pipeline


def _findings_json(categories):
    return json.dumps({"findings": [
        {"vuln_type": c, "category": c, "severity": "high", "evidence": f"{c} present", "confidence": 0.9}
        for c in categories
    ]})


# The teacher both scans and distills; branch on the distill prompt marker.
TEACHER_FINDINGS = ["hardcoded_credentials", "ssl_validation_bypass", "insecure_logging",
                    "insecure_webview_settings", "webview_arbitrary_url_load", "insecure_content_provider"]


def teacher_responder(system, user):
    if "playbook" in system.lower():  # distillation call
        return json.dumps({"lessons": [
            "Exported content providers without a signature-level permission expose their data to any app.",
            "WebView onReceivedSslError handlers that call proceed() disable TLS validation.",
            "Fix line 42 of the login screen.",  # instance-specific -> must be dropped
        ]})
    return _findings_json(TEACHER_FINDINGS)


def student_responder(system, user):
    # Baseline: finds 2. With lessons in the prompt: finds 5 (simulated learning).
    if "LESSONS:" in user:
        return _findings_json(["hardcoded_credentials", "insecure_logging", "ssl_validation_bypass",
                               "insecure_webview_settings", "webview_arbitrary_url_load"])
    return _findings_json(["hardcoded_credentials", "insecure_logging"])


def test_full_loop_measures_recall_lift(fake_app, gt_path):
    cfg = Config({
        "app": {"decompiled_path": fake_app, "source_globs": ["**/*.java", "**/*.xml"]},
        "ingest": {"max_file_bytes": 200000, "chunk": {"max_chars": 48000}},
        "lessons": {"max_lessons": 15, "enforce_generality": True},
        "match": {"strategy": "taxonomy"},
        "ground_truth": {"path": gt_path},
        "output": {"dir": "runs"},
    })
    teacher = MockClient("mock-teacher", responder=teacher_responder)
    student = MockClient("mock-student", responder=student_responder)

    result = run_pipeline(cfg, teacher_client=teacher, student_client=student, logger=lambda *_: None)

    assert round(result.recall_before, 4) == round(2 / 19, 4)
    assert round(result.recall_after, 4) == round(5 / 19, 4)
    assert result.recall_lift > 0
    # generality guard dropped the instance-specific "line 42" lesson
    assert len(result.lessons.lessons) == 2
    assert len(result.lessons.rejected) == 1
    # teacher is the reference ceiling and beats the student
    assert result.teacher_match.recall >= result.recall_after

    d = result.to_dict()
    assert d["recall"]["lift_absolute"] > 0
    assert set(d).issuperset({"recall", "matches", "lessons", "findings"})
    assert result.meta["valid_run"] is True


def test_repeats_averaging(fake_app, gt_path):
    cfg = Config({
        "app": {"decompiled_path": fake_app, "source_globs": ["**/*.java", "**/*.xml"]},
        "ingest": {"chunk": {"max_chars": 48000}},
        "match": {"strategy": "taxonomy"},
        "ground_truth": {"path": gt_path},
        "eval": {"repeats": 3},
    })
    teacher = MockClient("mock-teacher", responder=teacher_responder)
    student = MockClient("mock-student", responder=student_responder)
    result = run_pipeline(cfg, teacher_client=teacher, student_client=student, logger=lambda *_: None)

    assert result.meta["repeats"] == 3
    assert len(result.recall_before_samples) == 3
    assert len(result.recall_after_samples) == 3
    # deterministic mock => each sample identical => mean equals the single value
    assert round(result.recall_before, 4) == round(2 / 19, 4)
    assert round(result.recall_after, 4) == round(5 / 19, 4)
    assert result.to_dict()["recall"]["repeats"] == 3


def test_empty_teacher_marks_run_invalid(fake_app, gt_path):
    cfg = Config({
        "app": {"decompiled_path": fake_app, "source_globs": ["**/*.java", "**/*.xml"]},
        "match": {"strategy": "taxonomy"},
        "ground_truth": {"path": gt_path},
    })
    # teacher returns nothing (simulates rate-limit/quota exhaustion)
    teacher = MockClient("mock-teacher", responder=lambda s, u: "[]")
    student = MockClient("mock-student", responder=student_responder)
    result = run_pipeline(cfg, teacher_client=teacher, student_client=student, logger=lambda *_: None)
    assert result.meta["valid_run"] is False
    assert result.meta["teacher_empty"] is True
