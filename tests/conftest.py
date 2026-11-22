import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))  # make `apkscan` importable w/o install


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture
def gt_path() -> str:
    return str(REPO_ROOT / "data" / "ground_truth" / "insecureshop.yaml")


@pytest.fixture
def fake_app(tmp_path) -> str:
    """A tiny decompiled-app tree with a manifest + a couple of source files."""
    root = tmp_path / "decompiled"
    (root / "com" / "app").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(
        '<manifest><application>'
        '<activity android:name=".LoginActivity" android:exported="true"/>'
        '<provider android:name=".UserProvider" android:exported="true"/>'
        '</application></manifest>'
    )
    (root / "com" / "app" / "LoginActivity.java").write_text(
        "class LoginActivity {\n"
        "  String p = \"admin123\"; // hardcoded\n"
        "  void x(){ Log.d(\"creds\", p); webView.loadUrl(getIntent().getStringExtra(\"url\")); }\n"
        "}\n"
    )
    (root / "com" / "app" / "Web.java").write_text(
        "class Web { void onReceivedSslError(h,e){ h.proceed(); }\n"
        "  void s(){ settings.setJavaScriptEnabled(true); settings.setAllowFileAccess(true);} }\n"
    )
    return str(root)
