"""Unit tests for the deterministic (non-LLM) logic."""
from apkscan import taxonomy
from apkscan.config import Config
from apkscan.ingest import build_chunks, ingest
from apkscan.jsonutil import extract_findings_list, extract_json, extract_string_list
from apkscan.lessons import _looks_instance_specific, _banned_tokens
from apkscan.match import match_findings
from apkscan.schema import Finding, load_ground_truth


# ---- taxonomy -------------------------------------------------------------
def test_classify_known_patterns():
    assert taxonomy.classify("SSL error handler calls proceed()", "onReceivedSslError") == "ssl_validation_bypass"
    assert taxonomy.classify("hardcoded password in source") == "hardcoded_credentials"
    assert taxonomy.classify("Log.d writes credentials to logcat") == "insecure_logging"
    assert taxonomy.classify("nothing relevant here at all") is None


# ---- jsonutil -------------------------------------------------------------
def test_extract_json_from_fence_and_prose():
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('Sure! Here:\n[{"x": 2}]\nhope that helps') == [{"x": 2}]


def test_extract_findings_container_shapes():
    assert len(extract_findings_list('{"findings": [{"type":"a"},{"type":"b"}]}')) == 2
    assert len(extract_findings_list('[{"type":"a"}]')) == 1
    assert extract_string_list('{"lessons": ["r1", "r2"]}') == ["r1", "r2"]


# ---- ingest ---------------------------------------------------------------
def test_ingest_finds_manifest_and_prioritizes(fake_app, gt_path):
    cfg = Config({"app": {"decompiled_path": fake_app,
                          "source_globs": ["**/*.java", "**/*.xml"]},
                  "ingest": {"max_file_bytes": 200000, "chunk": {"max_chars": 48000}}})
    cb = ingest(cfg)
    assert cb.manifest is not None
    assert len(cb.files) == 2
    # WebView/SSL file should outrank or tie; manifest always in first chunk
    chunks = build_chunks(cb, 48000)
    assert chunks[0].text.startswith("\n===== FILE: AndroidManifest.xml")


# ---- matching + recall ----------------------------------------------------
def test_taxonomy_match_recall(gt_path):
    gt = load_ground_truth(gt_path)
    assert len(gt) == 19
    findings = [
        Finding(vuln_type="hardcoded pw", category="hardcoded_credentials").normalize(),
        Finding(vuln_type="ssl bypass", category="ssl_validation_bypass").normalize(),
        Finding(vuln_type="logs creds", category="insecure_logging").normalize(),
        Finding(vuln_type="totally bogus", category="not_a_real_category").normalize(),
    ]
    mr = match_findings(findings, gt, strategy="taxonomy")
    assert mr.total_gt == 19
    assert round(mr.recall, 4) == round(3 / 19, 4)
    assert len(mr.false_positives) == 1  # the bogus one


def test_fuzzy_match(gt_path):
    gt = load_ground_truth(gt_path)
    findings = [Finding(vuln_type="Insecure Logging", evidence="creds in logcat").normalize()]
    mr = match_findings(findings, gt, strategy="fuzzy", fuzzy_threshold=0.5)
    assert "GT-19" in mr.matched


# ---- lesson generality guard ---------------------------------------------
def test_generality_guard():
    banned = _banned_tokens([Finding(vuln_type="x", component="UserProvider", file="com/app/LoginActivity.java")])
    assert _looks_instance_specific("Fix line 42 of the activity", banned)
    assert _looks_instance_specific("The bug is in LoginActivity.java", banned)
    assert _looks_instance_specific("UserProvider is exported", banned)
    assert not _looks_instance_specific(
        "Exported content providers without a signature permission let any app read their data.", banned)
