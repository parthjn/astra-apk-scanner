"""Ingest a decompiled app: manifest + code + resources, chunked for scanning.

Design notes
------------
* Works on ANY decompiled tree (jadx, apktool, or a raw source dir). We never
  assume InsecureShop paths.
* We prioritize attack-surface files so that, under a token budget, the scanner
  sees the risky code first (manifest, exported components, WebView/Intent/
  Provider/crypto usage). This is the small-scale version of the retrieval
  strategy described in the 1M+ LOC section of the write-up.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import List, Optional

from .config import Config


@dataclass
class SourceFile:
    path: str          # path relative to decompiled root
    text: str
    priority: int = 0  # higher = scan earlier


@dataclass
class CodeBase:
    root: str
    manifest: Optional[SourceFile]
    files: List[SourceFile] = field(default_factory=list)

    @property
    def total_chars(self) -> int:
        n = len(self.manifest.text) if self.manifest else 0
        return n + sum(len(f.text) for f in self.files)


# Signals that a file touches a sensitive Android API -> scan it earlier.
_PRIORITY_SIGNALS = [
    (re.compile(r"loadUrl|WebView|setJavaScriptEnabled|onReceivedSslError|addJavascriptInterface", re.I), 5),
    (re.compile(r"ContentProvider|FileProvider|grantUriPermission|openFile", re.I), 5),
    (re.compile(r"getIntent|getParcelableExtra|startActivity|sendBroadcast|registerReceiver", re.I), 4),
    (re.compile(r"SharedPreferences|openFileOutput|MODE_WORLD|getExternalStorage", re.I), 3),
    (re.compile(r"Log\.[dviwe]\(|println|Cognito|AWS|TrustManager|HostnameVerifier", re.I), 3),
    (re.compile(r"password|secret|api[_-]?key|token|credential", re.I), 2),
]


def _file_priority(path: str, text: str) -> int:
    score = 0
    if path.lower().endswith(".xml"):
        score += 1
    for rx, weight in _PRIORITY_SIGNALS:
        if rx.search(text):
            score += weight
    return score


_GLOB_CACHE: dict = {}


def _glob_to_re(pat: str) -> "re.Pattern":
    """Translate a gitignore-style glob to a regex with correct ``**`` semantics:
      **  -> any run of chars incl. '/'      (``**/foo`` also matches ``foo``)
      *   -> any run of chars except '/'
      ?   -> one char except '/'
    This avoids fnmatch's trap where ``*`` spans '/', which made a pattern ending
    in ``/**`` (e.g. ``**/androidx/**``) match every file via its basename.
    """
    cached = _GLOB_CACHE.get(pat)
    if cached is not None:
        return cached
    i, n, out = 0, len(pat), ["(?s)^"]
    while i < n:
        if pat.startswith("**/", i):
            out.append("(?:.*/)?")   # zero or more leading dirs
            i += 3
        elif pat.startswith("**", i):
            out.append(".*")
            i += 2
        elif pat[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pat[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pat[i]))
            i += 1
    out.append("$")
    rx = re.compile("".join(out))
    _GLOB_CACHE[pat] = rx
    return rx


def _matches_any(path: str, patterns: List[str]) -> bool:
    return any(_glob_to_re(p).match(path) for p in patterns)


def _manifest_package(manifest_text: str) -> Optional[str]:
    """Extract the app package (e.g. 'com.example') from a decoded manifest."""
    m = re.search(r'package\s*=\s*"([a-zA-Z][\w.]+)"', manifest_text or "")
    return m.group(1) if m else None


def ingest(cfg: Config) -> CodeBase:
    root = cfg.decompiled_path
    if not root or not os.path.isdir(root):
        raise FileNotFoundError(
            f"Decompiled path not found: {root!r}. Run scripts/decompile.sh or set app.decompiled_path."
        )

    globs = cfg.source_globs
    exclude = cfg.get("ingest.exclude_globs", []) or []
    max_bytes = int(cfg.get("ingest.max_file_bytes", 200000))
    manifest_name = cfg.manifest_name

    manifest: Optional[SourceFile] = None
    files: List[SourceFile] = []

    for dirpath, _dirs, filenames in os.walk(root):
        for name in filenames:
            abs_path = os.path.join(dirpath, name)
            rel = os.path.relpath(abs_path, root)
            rel_posix = rel.replace(os.sep, "/")

            is_manifest = name == manifest_name
            if not is_manifest:
                if not _matches_any(rel_posix, globs):
                    continue
                if _matches_any(rel_posix, exclude):
                    continue

            try:
                if os.path.getsize(abs_path) > max_bytes:
                    continue
                with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue

            if is_manifest:
                manifest = SourceFile(path=rel_posix, text=text, priority=100)
            else:
                files.append(SourceFile(path=rel_posix, text=text, priority=_file_priority(rel_posix, text)))

    # Focus on the app's OWN code (read the package from the manifest) instead of
    # bundled libraries (kotlin stdlib, androidx, okhttp, ...). Fully general:
    # the package is whatever the manifest declares. Files under res/values*
    # (strings/arrays — a common home for secrets/config) are always kept.
    app_only = bool(cfg.get("ingest.app_package_only", True))
    always = cfg.get("ingest.always_include_globs", []) or []
    package = _manifest_package(manifest.text) if manifest else None
    if app_only and package:
        pkg_path = "/" + package.replace(".", "/") + "/"
        kept = [f for f in files if pkg_path in ("/" + f.path) or _matches_any(f.path, always)]
        # graceful fallback: if focusing would drop everything, keep all files
        if kept:
            files = kept

    # highest priority first; stable by path for determinism
    files.sort(key=lambda f: (-f.priority, f.path))

    hard_cap = int(cfg.get("ingest.chunk.hard_cap_files", 0) or 0)
    if hard_cap > 0:
        files = files[:hard_cap]

    return CodeBase(root=root, manifest=manifest, files=files)


@dataclass
class Chunk:
    index: int
    text: str
    files: List[str]


def build_chunks(cb: CodeBase, max_chars: int) -> List[Chunk]:
    """Pack files into chunks under `max_chars`. The manifest is prepended to the
    FIRST chunk and also kept as context; each file is delimited so the model can
    cite paths. A single oversized file is hard-split.
    """
    chunks: List[Chunk] = []
    buf: List[str] = []
    buf_files: List[str] = []
    size = 0

    def flush():
        nonlocal buf, buf_files, size
        if buf:
            chunks.append(Chunk(index=len(chunks), text="\n".join(buf), files=list(buf_files)))
            buf, buf_files, size = [], [], 0

    def add_block(path: str, text: str):
        nonlocal size
        block = f"\n===== FILE: {path} =====\n{text}\n"
        if size + len(block) > max_chars and buf:
            flush()
        # hard-split a single file larger than the budget
        if len(block) > max_chars:
            header = f"\n===== FILE: {path} (split) =====\n"
            body = text
            step = max_chars - len(header) - 32
            for i in range(0, len(body), step):
                part = header + body[i:i + step] + "\n"
                if buf:
                    flush()
                chunks.append(Chunk(index=len(chunks), text=part, files=[path]))
            return
        buf.append(block)
        buf_files.append(path)
        size += len(block)

    if cb.manifest:
        add_block(cb.manifest.path, cb.manifest.text)
    for f in cb.files:
        add_block(f.path, f.text)
    flush()
    return chunks
