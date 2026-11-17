# Security review — release 1.0.0

Review of the Android app, its native code and the backend before the first release (2026-11-14). Each item lists
what was checked, how, the result and what changed. Re-run this list before every MINOR release.

## Android app

### Exported components

Checked in the merged release manifest (`aapt2 dump xmltree --file AndroidManifest.xml app-release-unsigned.apk`).

| Component | Exported | Protection | Notes |
| --- | --- | --- | --- |
| `MainActivity` | yes | — (launcher) | **Finding, fixed:** accepted deep-link extras from any app (see below) |
| `InternalEntry` (alias of `MainActivity`) | no | — | New: the only entry that honours deep-link extras |
| `WebShieldTileService` | yes | `BIND_QUICK_SETTINGS_TILE` | Only System UI can bind |
| `WebShieldVpnService` | no | `BIND_VPN_SERVICE` | System only |
| `RealtimeProtectionService` | no | — | |
| Boot, alert and blocked-page receivers | no | — | Actions checked in `onReceive` |
| WorkManager `SystemJobService` | yes | `BIND_JOB_SERVICE` | Library; system only |
| WorkManager `DiagnosticsReceiver`, `ProfileInstallReceiver` | yes | `DUMP` | Library; shell/system only |
| `InitializationProvider` | no | — | |

No exported content provider; no `android:debuggable`; no `usesCleartextTraffic`.

### Intent validation

**Finding (medium), fixed.** `MainActivity` is exported and read `EXTRA_FILE_RESULT` (a serialized scan result) and
`EXTRA_SHOW_PACKAGE` from any intent. Any installed app could start BlackShield showing a forged result, for example
"clean" for a malicious APK, which is a phishing aid against a security app.
Fix: the app's own notifications, tile and VPN settings link now target `InternalEntry`, a non-exported
`activity-alias`; `MainActivity.handle()` ignores extras unless `intent.component` is that alias
(`core/data/AppEntry.kt`). Only this app's PendingIntents can reach it.

Other checks:
- All PendingIntents use `FLAG_IMMUTABLE` and explicit components (grep of `PendingIntent.get*`).
- Receivers are not exported and check the action; extras they read (`EXTRA_SHA256`, `EXTRA_DOMAIN`) only act on
  the app's own state (ignore an alert, allow a domain once) and come from immutable PendingIntents.
- `RealtimeProtectionService` reads package names from system package broadcasts registered at runtime.
- URIs from the file picker are used with the persisted permission the user granted; nothing is opened from
  arbitrary intent URIs.

### Network

- `network_security_config.xml` (release): `cleartextTrafficPermitted="false"`, system trust anchors only. The debug
  variant additionally allows cleartext to the local backend (10.0.2.2, localhost, 127.0.0.1) only.
- OkHttp certificate pinning is supported (`blackshield.certificatePins`); the release workflow refuses to build
  without pins (`docs/release.md`).
- The API key is sent only to the API's own origin (`ApiHeadersInterceptor`); HTTP logging is debug-only.

### Logs

- Release builds plant no Timber tree, and R8 removes `Log.v/d/i/w` and all Timber calls
  (`app/proguard-rules.pro`, `-assumenosideeffects`).
- Verified on the R8 build on the emulator: `adb logcat --pid=<pid>` shows only ART runtime lines, nothing from
  the app, during onboarding, a full scan and real-time protection start.
- Debug logs never contain domains (Web Shield policy), file contents or keys.

### Secrets and tokens

- No user accounts or session tokens exist. The only credential is the build's API key, which is extractable from
  any APK and treated as public (see [attestation.md](attestation.md)); it is injected at build time from CI secrets,
  never committed.
- Keys that must stay on the device are in the Android Keystore: the quarantine keyset is wrapped by a Keystore AES
  key (Tink `AndroidKeysetManager`). If a per-install token is added later (attestation option B), it must be a
  Keystore key pair, never a value in SharedPreferences or DataStore.
- Signing keys, YARA rule signing key: never in the repository (`*.jks`, `*.keystore`, `.env*` git-ignored);
  release signing reads environment variables or `~/.gradle/gradle.properties`.

### R8 / ProGuard

- Release: `isMinifyEnabled = true`, `isShrinkResources = true`. Libraries ship their own consumer rules; the
  scanner keeps its JNI entry points (`consumer-rules.pro`).
- Verified with the `benchmark` variant (release configuration, debug key) on the emulator: onboarding, the
  notification permission, the real-time protection service, a full scan of 261 apps with native hashing and YARA
  (the YARA test app was detected), Room, DataStore, WorkManager and kotlinx.serialization all work; no
  `ClassNotFoundException`, `NoSuchMethodError` or `UnsatisfiedLinkError` in logcat. APK size: 3.1 MB (debug: 17 MB).

### Tamper and debuggable checks

`AppIntegrity` (release builds only): if the app is debuggable or signed by a certificate whose SHA-256 is not in
`BLACKSHIELD_RELEASE_CERT_SHA256`, it shows a "modified copy" screen with an Uninstall button and starts no services.
This stops casual repackaging; it is not a defence against a determined attacker, and the backend never relies on it.
Backend-side options (Play Integrity, key attestation) are in [attestation.md](attestation.md).

### Backups and data at rest

`allowBackup=false`, empty data-extraction rules. Quarantined files are encrypted (Tink streaming AEAD, AES-256-GCM),
bound to their file name; other data relies on file-based encryption of app-private storage.

## Native code

### Hardening flags

Every native target, libyara included (`core/scanner/src/main/cpp/CMakeLists.txt`):
`-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2` (release and the always-optimised scan core), `-Wl,-z,relro,-z,now`
(full RELRO), `-Wl,-z,noexecstack`. Shared libraries are PIC and NDK executables PIE by default. Warnings are
errors for our code.

### Sanitizers

The GoogleTest suite (123 tests) runs on the emulator under AddressSanitizer + UndefinedBehaviorSanitizer and under
UBSan alone (`./gradlew :core:scanner:connectedNativeTest -PnativeSanitize=address,undefined`), in CI on every change.

Findings, all fixed:

| # | Where | Finding | Fix |
| --- | --- | --- | --- |
| 1 | libyara `compiler.c`, `scanner.c` | `yr_object_destroy` (returns void) called through an `int (*)(void*)` pointer (UBSan `-fsanitize=function`) | Correctly typed wrapper |
| 2 | Memory-budget test | Not a bug: ASan's shadow memory exceeds the 1 MiB RSS budget | Test skips itself under ASan |

Result: 122 passed, 1 skipped (the memory budget test, which passes in the normal build); no sanitizer reports.

### Fuzzing

`yara_scan_fuzzer` (libFuzzer + ASan + UBSan, on the emulator): `YaraScanner::ScanMemory` with rules that load the
`dex` and `math` modules, so every input goes through libyara's DEX parser, the entropy code and the string matcher,
the path that runs over DEX files from untrusted APKs. Seeds: the project's own test APKs' DEX files.
`./gradlew :core:scanner:connectedNativeFuzz -PfuzzSeconds=N`; CI fuzzes 5 minutes per change.

| # | Where | Finding | Fix |
| --- | --- | --- | --- |
| 3 | libyara `dex.c` `read_uleb128_bounded` | Signed integer overflow: `cur << 28` with `cur` promoted to `int` (UBSan) | Shift done on `uint32_t` |
| 4 | libyara `dex.c` map list | Misaligned `uint32_t` read at a file-controlled offset (UB; can fault on 32-bit ARM) | `__builtin_memcpy` |
| 5 | ASan runtime on the emulator | False `CHECK failed ... kAllocBegMagic` after ~10⁴ runs: ASan's periodic release of free memory to the OS zeroes allocator metadata of quarantined chunks. Reproduced with inputs that match nothing; disappears with `allocator_release_to_os_interval_ms=-1` or `quarantine_size_mb=0`, which a real heap corruption would not | Release-to-OS disabled in the sanitizer runs (detection unaffected) |

libyara fixes are applied to the pinned tarball at configure time by `cmake/patch-libyara.cmake`, which fails the build
if the patched code changes in an upgrade. They should also be reported upstream (VirusTotal/yara).

The JVM-side parsers (binary manifest, ZIP directory, DEX extraction, signing certificates) are fuzzed with Jazzer
(`ParserFuzzTest`): seeds and every reproducer run as unit tests on each build; `JAZZER_FUZZ=1` fuzzes them.

| # | Where | Finding | Fix |
| --- | --- | --- | --- |
| 6 | `BinaryXmlReader.StringPool` (our manifest parser) | **High.** A string pool whose declared size exceeds the file, or whose string offset overflows `Int`, made the parser throw `IndexOutOfBoundsException` instead of `ManifestParseException`. Callers only expect the latter and nothing above them catches broadly, so the exception would propagate out of the analyzer: a crafted APK on the device could end a full scan early or crash the real-time protection service, a way for malware to avoid detection. Found by Jazzer in 210 s | Pool size checked against the file; offsets computed in `Long`; `ManifestParser.parse` now also turns any unexpected runtime exception into `ManifestParseException`, so a future parser bug degrades to "manifest unreadable" instead of a failed scan. The reproducer is a regression test (`ParserFuzzTestInputs/manifest/string-pool-beyond-file.axml`) |

Campaigns for 1.0.0 (emulator x86_64 for native, Windows host JVM for Jazzer), all ending without findings after the
fixes above:

| Target | Time | Executions | Coverage |
| --- | --- | --- | --- |
| `yara_scan_fuzzer` (ASan + UBSan), after fixes 3–4 | 10 + 15 + 15 min | 4,855 + 5,005 + 35,498 | 759–774 edges |
| `ParserFuzzTest.manifest`, after fix 6 | 5 min | 32,595,009 | 313 edges |
| `ParserFuzzTest.apkContents` | 5 min | 307,521 | 168 edges |
| `ParserFuzzTest.dexEntries` | 5 min | 278,865 | 165 edges |
| `ParserFuzzTest.certificate` | 2 min | 6,903,047 | 11 edges (the JDK's X.509 parser is not instrumented) |

## Backend

- Dependencies: `pip-audit` reports no known vulnerabilities (2026-11-14); CI runs it with `--strict`.
- Auth: API keys stored as SHA-256 hashes only; constant-time comparison; failing keys rate limited per IP.
- Input limits: 16 KiB bodies (API and Nginx), strict schemas (`extra="forbid"` on crash reports, patterns that
  forbid free text).
- Logs and metrics carry no IPs, keys, hashes or query strings.
- Production: TLS 1.2/1.3 only, HSTS, no docs or metrics on the public listener, internal networks for API and
  database, read-only containers without capabilities. See [backend-operations.md](backend-operations.md).

## Open items

- Report the three libyara issues upstream.
- Longer fuzz campaigns (hours, ideally continuous, e.g. OSS-Fuzz/ClusterFuzzLite) and an arm64 run on a phone.
- Add attestation before any non-public or write endpoint beyond crash reports ([attestation.md](attestation.md)).
- Run the popular-apps false-positive test on a device with the 200 apps installed before each release (the
  emulator image has few of them; see [testing.md](testing.md#false-positives)).
