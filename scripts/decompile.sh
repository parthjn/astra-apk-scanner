#!/usr/bin/env bash
# Download + decompile an APK into data/decompiled/<name>/ using jadx.
# Usage:
#   scripts/decompile.sh <apk-url-or-path> [output-name]
#
# Requires: jadx (brew install jadx) and a JRE. We decompile to Java sources,
# which are far more LLM-friendly than smali. Point config app.decompiled_path
# at the resulting directory.
set -euo pipefail

SRC="${1:?usage: decompile.sh <apk-url-or-path> [name]}"
NAME="${2:-app}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/data/decompiled/$NAME"
WORK="$(mktemp -d)"

if ! command -v jadx >/dev/null 2>&1; then
  echo "jadx not found. Install it: brew install jadx   (or https://github.com/skylot/jadx)" >&2
  exit 1
fi

# Fetch the APK into an isolated dir (treat downloads as untrusted input).
if [[ "$SRC" =~ ^https?:// ]]; then
  echo "Downloading $SRC ..."
  curl -fsSL "$SRC" -o "$WORK/app.apk"
  APK="$WORK/app.apk"
else
  APK="$SRC"
fi

echo "Decompiling -> $OUT"
rm -rf "$OUT"
# -d output dir; jadx writes sources/ and resources/ (incl. AndroidManifest.xml)
jadx --no-debug-info --show-bad-code -d "$OUT" "$APK" || true  # jadx returns !=0 on partial decompile

echo "Done. Set app.decompiled_path: $OUT"
echo "Manifest: $(find "$OUT" -name AndroidManifest.xml | head -1)"
