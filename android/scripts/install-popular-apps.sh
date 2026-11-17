#!/usr/bin/env bash
# Installs the APKs of popular apps from a local folder onto the connected test device, for
# PopularAppsFalsePositiveTest (see docs/testing.md). The folder holds one *.apk per app, or one sub-folder per app
# with its split APKs (base.apk, split_config.*.apk), e.g. exported from a test phone with `adb shell pm path`.
# Use APKs you are entitled to (your own test phone's apps); this script downloads nothing.
set -euo pipefail
dir="${1:?usage: install-popular-apps.sh <folder>}"
ok=0; failed=0
for item in "$dir"/*; do
  if [[ -d "$item" ]]; then
    mapfile -t splits < <(find "$item" -maxdepth 1 -name '*.apk' | sort)
    ((${#splits[@]})) || continue
    if adb install-multiple -r -g "${splits[@]}" >/dev/null; then ok=$((ok + 1)); else failed=$((failed + 1)); echo "failed: $item"; fi
  elif [[ "$item" == *.apk ]]; then
    if adb install -r -g "$item" >/dev/null; then ok=$((ok + 1)); else failed=$((failed + 1)); echo "failed: $item"; fi
  fi
done
echo "installed $ok, failed $failed"
