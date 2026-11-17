# Releasing BlackShield

## Versioning

- One semantic version, `MAJOR.MINOR.PATCH`, in `android/gradle.properties` (`blackshield.versionName`).
- The version code is derived: `MAJOR * 10000 + MINOR * 100 + PATCH` (1.0.0 → 10000, 1.2.3 → 10203). MINOR and PATCH
  stay below 100; the build fails otherwise. Every upload to Play needs a higher code, so every release bumps the
  version.
- PATCH: fixes only. MINOR: features, new permissions or data handling changes (also update
  [privacy.md](privacy.md), the privacy policy and the Play declarations). MAJOR: breaking backend protocol changes.
- The backend has its own version (`backend/pyproject.toml`); API compatibility is kept by `/v1`.

## Signing

Google Play App Signing: Google holds the **app signing key**; we sign uploads with an **upload key**.

1. Create the upload key once, on a trusted machine, and store the keystore and its passwords in the password manager
   (two people with access; Google can reset a lost upload key, not a lost app signing key):

   ```bash
   keytool -genkeypair -v -keystore blackshield-upload.jks -alias upload -keyalg RSA -keysize 4096 -validity 10000
   ```

2. CI secrets (repository environment `release`, with required reviewers):

   | Secret | Value |
   | --- | --- |
   | `BLACKSHIELD_UPLOAD_KEYSTORE_BASE64` | `base64 -w0 blackshield-upload.jks` |
   | `BLACKSHIELD_KEYSTORE_PASSWORD`, `BLACKSHIELD_KEY_ALIAS`, `BLACKSHIELD_KEY_PASSWORD` | From step 1 |
   | `BLACKSHIELD_API_BASE_URL` | `https://api.<your domain>/` |
   | `BLACKSHIELD_API_KEY` | From `blackshield-signatures generate-api-key --id android-v1` |
   | `BLACKSHIELD_CERTIFICATE_PINS` | `api.<domain>:<base64 SPKI SHA-256 of the current key>,api.<domain>:<backup key>` |
   | `BLACKSHIELD_RELEASE_CERT_SHA256` | SHA-256 of the Play app signing certificate and of the upload certificate (Play Console > App integrity), comma-separated |
   | `BLACKSHIELD_YARA_RULES_PUBLIC_KEYS` | `k1:<base64 SPKI>` from `blackshield-signatures rules-keygen` |
   | `PLAY_SERVICE_ACCOUNT_JSON` | Optional: service account with release rights, for automatic internal-track uploads |

3. Local signed builds read the same names as Gradle properties in `~/.gradle/gradle.properties`
   (`blackshield.keystoreFile`, `blackshield.keystorePassword`, `blackshield.keyAlias`, `blackshield.keyPassword`, ...)
   or as environment variables. Nothing secret is ever committed; `*.jks` and `*.keystore` are git-ignored.

Without signing settings, `assembleRelease` produces an unsigned APK (useful for checks); with
`BLACKSHIELD_REQUIRE_RELEASE_SIGNING=true` (CI) a missing keystore fails the build. With
`BLACKSHIELD_RELEASE_CERT_SHA256` empty, the app's modified-copy check is off, so release CI requires it.

## Release steps

1. Update `CHANGELOG.md`: move `[Unreleased]` items into `## [x.y.z] - date`.
2. Bump `blackshield.versionName`. Commit both: `chore(release): x.y.z`.
3. Run the device suites on an emulator (CI runs them on every change; repeat locally for a release):

   ```bash
   cd android
   ./gradlew connectedDebugAndroidTest :core:scanner:connectedNativeTest
   ./gradlew :core:scanner:connectedNativeTest -PnativeSanitize=address,undefined
   ./gradlew :core:scanner:connectedNativeFuzz -PfuzzSeconds=1800
   ```

4. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`. `.github/workflows/release.yml` checks the tag against
   the version and changelog, runs the checks, builds the signed AAB and APK, verifies the signature and that the
   build is not debuggable, uploads the artifacts (with `mapping.txt` for de-obfuscating stack traces), drafts a
   GitHub release and, with a Play service account, uploads to the internal testing track.
5. Go through the internal testing checklist below, then promote in Play Console: internal → closed → production
   (staged rollout 10 % → 50 % → 100 %, watching crash reports and `blackshield_http_requests_total` by status).

Keep `mapping.txt` for every released version: crash report frames from release builds are obfuscated and are
read with `retrace mapping.txt stacktrace.txt`.

## Internal testing track checklist

Install from the Play internal testing link (not a side-loaded APK) on at least: one Android 8 (API 26) device, one
Android 14+, one 32-bit ARM device if available, a Samsung and a Pixel.

**Install and first run**
- [ ] Installs from Play; the app opens without the "modified copy" screen (checks the Play app signing certificate).
- [ ] Onboarding: notification permission prompt, VPN consent; skipping each works.
- [ ] Settings shows the right version; the build is not debuggable (`adb shell run-as com.blackshield.app` fails).

**Core flows**
- [ ] Full scan finishes; the test APKs (`:testing:eicar-apk` is detected only by debug builds, so use a known test
      sample from the signature feed or a YARA test file) are flagged.
- [ ] Real-time: installing a flagged app shows a warning within seconds; Uninstall works.
- [ ] Download monitoring (Android 11+ with All files access): a flagged APK in Download is detected; quarantine,
      restore and delete work.
- [ ] Web Shield: a domain from the blocklist does not resolve and shows the notification; Allow once works; normal
      browsing works; switching Wi-Fi ↔ mobile keeps it working; always-on VPN can be enabled.
- [ ] Signature, domain and rule sync succeed against production (Settings shows the new versions).
- [ ] Scheduled scan runs (`adb shell cmd jobscheduler run -f com.blackshield.app <id>` or wait a day).
- [ ] History filters and JSON/PDF export.

**Privacy and resilience**
- [ ] Crash reports off by default; with them on, a forced crash (internal builds only) appears in `crash_reports`
      after restart; turned off, nothing is sent.
- [ ] `adb logcat --pid=$(adb shell pidof com.blackshield.app)` shows no app log lines.
- [ ] Airplane mode: the app works offline, sync retries later.
- [ ] Uzbek and Russian: no truncated or untranslated text; dark and light themes; TalkBack on the main screens.

**Store and console**
- [ ] Play pre-launch report: no crashes, no accessibility or security warnings left unexplained.
- [ ] Declarations and Data safety match [play-policy-checklist.md](play-policy-checklist.md).
- [ ] Android vitals after internal testing: crash-free > 99.5 %, ANR rate < 0.2 %.
