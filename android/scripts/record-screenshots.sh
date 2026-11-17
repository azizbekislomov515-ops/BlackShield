#!/usr/bin/env bash
# Records screenshot goldens on the connected (reference) emulator and copies them into each module's
# src/androidTest/assets/screenshots/. Review the diff before committing. See docs/testing.md.
set -euo pipefail
cd "$(dirname "$0")/.."
modules=(feature/home feature/scan feature/threats feature/settings)
tasks=()
for m in "${modules[@]}"; do tasks+=(":${m//\//:}:connectedDebugAndroidTest"); done
./gradlew "${tasks[@]}" -Pandroid.testInstrumentationRunnerArguments.recordScreenshots=true
for m in "${modules[@]}"; do
  out="$m/src/androidTest/assets/screenshots"
  mkdir -p "$out"
  find "$m/build/outputs/connected_android_test_additional_output" -name '*.png' ! -name '*.actual.png' -exec cp {} "$out/" \;
  echo "$m: $(ls "$out" | wc -l) golden(s)"
done
