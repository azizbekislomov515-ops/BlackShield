# Testing

## Gates (every change, CI)

```bash
cd android
./gradlew ktlintFormat
./gradlew testDebugUnitTest lint detekt ktlintCheck
```

Lint runs with warnings as errors. It also catches hardcoded UI text (`SetTextI18n`, `HardcodedText`) and missing
translations: every string exists in `values` (English), `values-uz` (Uzbek, Latin script) and `values-ru` (Russian).

## Device tests

Run them on an emulator or a test phone. The quarantine end-to-end tests clear the device's lists of detected and
quarantined files.

```bash
./gradlew connectedDebugAndroidTest
```

| Suite | What it covers |
| --- | --- |
| `:app` `MainFlowsTest` | The real app end to end: onboarding to dashboard (shown once); *Scan now* runs a full scan, then Threats, History (the scan is listed) and a daily schedule in Settings (checked in WorkManager, with the charging constraint); a harmful file quarantined from the Threats screen (original removed, vault file encrypted, restore gives back the same bytes); a quarantined file deleted after confirming (encrypted copy gone). |
| `:app` `RealtimeProtectionTest`, `WebShieldTest` | Real-time protection and Web Shield (see their KDoc). |
| `:feature:home` | Dashboard: score and level, *Scan now*, each improvement links to its fix; onboarding steps. |
| `:feature:scan` | Idle, running (pause, cancel) and finished (flagged apps open their details). |
| `:feature:threats` | Uninstall, quarantine, restore and delete actions; empty state; History filters (date, verdict, source) and PDF/JSON export. |
| `:feature:settings` | Schedule frequency and charging/idle conditions; theme. |
| `:core:data` | Room migrations up to v4 against the exported schemas, repositories, signature store scale. |

### Accessibility checks

Compose UI tests call `setThemedContent` (`:testing:ui`) or `enableAccessibilityChecks()`. The Accessibility Test
Framework then checks the screen on every action the test performs and on `checkAccessibility()`. A test fails on a
touch target under 48 dp, a control without a label, text contrast below WCAG AA, and similar problems.

Manual TalkBack check before a release: go through onboarding, the dashboard (the score is read as "Security score N
of 100", each improvement as one button), a scan, the Threats actions and the History filters. Every control should
be announced with its name and role, and status labels in capitals are read as normal words.

### Screenshot tests

Key screens are compared with goldens in each module's `src/androidTest/assets/screenshots/`. Dashboard (dark and
light), onboarding, scan (running and finished), threats, history and the schedule settings.

- Goldens are recorded on the reference emulator: API 37, 1080×2400, 420 dpi, English. On a device whose capture
  has a different size the comparison is skipped, not failed.
- A match allows up to 0.4 % of pixels to differ by more than 24 per channel (text anti-aliasing).
- A failing test saves `<name>.actual.png`. The test storage service pulls it into
  `build/outputs/connected_android_test_additional_output/`.
- After an intended UI change, re-record and review the image diff before committing:

```bash
./scripts/record-screenshots.sh
```

## Native tests, sanitizers and fuzzing

```bash
cd android
./gradlew :core:scanner:connectedNativeTest                                   # GoogleTest suite (hardened release flags)
./gradlew :core:scanner:connectedNativeTest -PnativeSanitize=address,undefined # under ASan + UBSan
./gradlew :core:scanner:connectedNativeTest -PnativeSanitize=undefined         # UBSan alone
./gradlew :core:scanner:connectedNativeFuzz -PfuzzSeconds=600                  # libFuzzer + ASan + UBSan
```

All run on the connected device or emulator (x86_64 by default, `-PnativeTestAbi=arm64-v8a` for a phone). Any
sanitizer report fails the task. The fuzz task starts from `src/nativeFuzz/corpus/<target>/`, stops at the first
finding and pulls the reproducer into `build/native-fuzz/findings/<target>/`; reproduce on the device with
`./yara_scan_fuzzer <file>` (with the ASan runtime from the NDK on `LD_LIBRARY_PATH`) and symbolize offsets with the
NDK's `llvm-symbolizer --obj=build/native-fuzz/<abi>/native-fuzz/yara_scan_fuzzer --relative-address <offset>`.
Fixed reproducers are worth adding to the corpus.

### Fuzzing

| Target | Code | How it runs |
| --- | --- | --- |
| `yara_scan_fuzzer` (native) | `YaraScanner::ScanMemory` with the `dex` and `math` modules loaded: libyara's DEX parser, entropy, string matcher | `connectedNativeFuzz` (5 min in CI, 30 min before a release) |
| `ParserFuzzTest.manifest` (JVM) | Binary `AndroidManifest.xml` parser | Jazzer |
| `ParserFuzzTest.apkContents` (JVM) | ZIP directory pass and manifest extraction | Jazzer |
| `ParserFuzzTest.dexEntries` (JVM) | DEX extraction from the ZIP with size limits | Jazzer |
| `ParserFuzzTest.certificate` (JVM) | Signing certificate description | Jazzer |

The Jazzer tests replay their seeds (`src/test/resources/.../ParserFuzzTestInputs/<test>/`) and every saved
reproducer as part of `testDebugUnitTest`. To fuzz:

```bash
JAZZER_FUZZ=1 ./gradlew :core:scanner:testDebugUnitTest --tests '*ParserFuzzTest*'
```

Each test then fuzzes for its `maxDuration` and writes any crashing input next to the seeds, where it becomes a
regression test.

## False positives

`PopularAppsFalsePositiveTest` (`:core:scanner` instrumented) scans every app from the 200-app list
(`src/androidTest/assets/popular_apps.txt`) that is installed on the device, with the shipped risk rules and YARA
rules. It fails if any is malicious or more than 1 % are suspicious, and logs each app's score and rules under the
tag `PopularApps`.

```bash
./scripts/install-popular-apps.sh ~/popular-apks     # APKs from your own test phone; downloads nothing
./gradlew :core:scanner:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=com.blackshield.core.scanner.analysis.PopularAppsFalsePositiveTest \
  -Pandroid.testInstrumentationRunnerArguments.requirePopularApps=150
```

The stock emulator image has only a handful of these apps, so run it on a test phone with the apps installed from
Play before each release. Preinstalled system apps are covered on every device by
`InstalledAppsAnalysisTest.systemAppsAreNeverFlagged`.
