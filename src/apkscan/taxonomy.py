"""App-agnostic Android vulnerability taxonomy.

Model findings come back as free text ("SSL error handler ignores cert errors").
To match them against ground truth *across apps*, we normalize both sides onto a
small canonical taxonomy drawn from OWASP MASVS / Mobile Top 10 categories.

This file contains NOTHING specific to InsecureShop. Categories are generic
Android weakness classes; the keyword aliases are the signals a scanner would
emit for any app. Add a category here and it works for every app.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

# canonical_category -> list of lowercase keyword/alias signals
TAXONOMY: Dict[str, List[str]] = {
    "hardcoded_credentials": [
        "hardcoded credential", "hardcoded password", "hard-coded", "embedded credential",
        "api key in", "secret in code", "hardcoded secret", "credentials embedded",
    ],
    "webview_arbitrary_url_load": [
        "arbitrary url", "load arbitrary", "webview loadurl", "deeplink loads",
        "insufficient url validation", "unvalidated url", "open redirect in webview",
    ],
    "weak_host_validation": [
        "host validation", "weak host", "host check bypass", "endswith host",
        "contains host", "domain validation bypass",
    ],
    "arbitrary_code_execution": [
        "arbitrary code execution", "createpackagecontext", "code execution",
        "dynamic code loading", "dexclassloader", "third-party package context",
        "remote code execution", "rce",
    ],
    "intent_redirection": [
        "intent redirection", "embedded intent", "getparcelableextra", "nested intent",
        "access to protected component", "intent forwarding", "startactivity(intent)",
        "intent passed to startactivity",
    ],
    "webview_untrusted_data_uri": [
        "data uri", "data: uri", "untrusted uri", "unprotected data uri",
    ],
    "arbitrary_file_theft": [
        "file theft", "steal file", "arbitrary file read", "exfiltrate local file",
        "chooseractivity", "content:// to file", "file:// read",
    ],
    "known_vulnerable_component": [
        "known vulnerab", "outdated library", "vulnerable dependency", "cve-",
        "vulnerable component", "outdated component",
    ],
    "insecure_broadcast_receiver": [
        "broadcast receiver", "registerreceiver", "dynamic receiver", "web_url",
        "exported receiver", "unprotected broadcast",
    ],
    "cloud_credential_misconfig": [
        "cognito", "aws", "s3 bucket", "cloud misconfig", "identity pool",
        "access key", "firebase misconfig",
    ],
    "insecure_fileprovider": [
        "fileprovider", "file_paths", "root-path", "external-path", "cache-path",
        "over-broad path", "provider_paths", "grant uri permission",
    ],
    "implicit_intent_sensitive_data": [
        "implicit intent", "sendbroadcast", "implicit broadcast", "sensitive data in intent",
        "broadcast sensitive", "implicit intent broadcast",
    ],
    "implicit_intent_url_interception": [
        "intercept implicit", "implicit intent to load", "intent interception",
        "hijack intent", "intercepting implicit intent",
    ],
    "insecure_setresult": [
        "setresult", "set result", "result activity", "activity result leaks",
    ],
    "insecure_content_provider": [
        "content provider", "exported provider", "contentprovider", "query provider",
        "provider exported", "grantUriPermissions",
    ],
    "ssl_validation_bypass": [
        "onreceivedsslerror", "ssl error", "sslerrorhandler", "proceed()",
        "certificate validation", "trustmanager", "hostnameverifier", "disable ssl",
        "ignore ssl", "allow_all_hostname",
    ],
    "insecure_webview_settings": [
        "setjavascriptenabled", "setallowfileaccess", "setallowuniversalaccess",
        "setallowcontentaccess", "addjavascriptinterface", "webview settings",
        "file access from file urls", "insecure webview propert",
    ],
    "insecure_data_storage": [
        "insecure data storage", "sharedpreferences", "mode_world_readable",
        "plaintext storage", "unencrypted storage", "stored in cleartext",
        "cleartext credential",
    ],
    "insecure_logging": [
        "insecure logging", "log.d", "log.v", "log.i", "log.e", "logcat",
        "logs credential", "sensitive data logged", "println",
    ],
    # Generic Android weakness classes shared across many apps
    "weak_cryptography": [
        "weak crypto", "weak cipher", "insecure cipher", "ecb", "ecb mode",
        "secretkeyspec", "cipher.getinstance", "hardcoded key", "hardcoded encryption key",
        "hardcoded iv", "static iv", "md5 hash", "des encryption", "3des", "ivparameterspec",
    ],
    "backup_allowed": [
        "allowbackup", "android:allowbackup", "backup enabled", "adb backup", "allow backup",
    ],
    "debuggable_app": [
        "android:debuggable", "debuggable true", "debuggable flag", "debuggable=\"true\"",
    ],
    # Generic fallback buckets (still useful on unseen apps)
    "cleartext_traffic": ["cleartext traffic", "usescleartexttraffic", "http://", "clear-text", "insecure http"],
    "exported_component_no_permission": [
        "exported", "android:exported", "no permission", "missing permission",
        "unprotected activity", "unprotected service",
    ],
    "insufficient_input_validation": [
        "input validation", "unvalidated input", "injection", "path traversal",
    ],
}

# Normalize a free-text label (strip punctuation, collapse spaces).
_NORM = re.compile(r"[^a-z0-9]+")


def _norm(text: str) -> str:
    return _NORM.sub(" ", (text or "").lower()).strip()


def canonical_categories() -> List[str]:
    return list(TAXONOMY.keys())


def classify(*text_fields: str) -> Optional[str]:
    """Map arbitrary finding text onto a canonical category.

    Scans the concatenated fields (type, title, evidence, ...) for the strongest
    alias hit. Returns None if nothing matches, so callers can decide how to
    treat unclassifiable findings (we keep them, uncategorized, as potential FPs).
    """
    blob = " ".join(_norm(t) for t in text_fields if t)
    if not blob:
        return None

    best_cat: Optional[str] = None
    best_score = 0
    for cat, aliases in TAXONOMY.items():
        score = 0
        for alias in aliases:
            a = _norm(alias)
            if a and a in blob:
                # longer, more specific aliases weigh more
                score += len(a)
        if score > best_score:
            best_score, best_cat = score, cat
    return best_cat
