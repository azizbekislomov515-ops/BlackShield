# Changelog

All notable changes to BlackShield (Android app and backend). The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/).
The app version lives in `android/gradle.properties` (`blackshield.versionName`); the release workflow refuses a tag
without a matching section here.

## [Unreleased]

## [1.0.0] - 2026-11-14

First public release.

### App

- Malware scan of every installed app: signature matching (MD5/SHA-1/SHA-256), static analysis with a rule-based risk
  engine, and YARA rules over APK and DEX content, all on the device.
- Real-time protection: new and updated apps and new APK downloads are checked as they appear, with a warning and
  one-tap uninstall.
- Quarantine for harmful APK files, encrypted in app-private storage (restore or delete permanently); guided
  uninstall for harmful apps.
- Web Shield: on-device DNS filtering of malware and phishing domains through a local VPN, with "Allow once" and an
  allowlist.
- Home dashboard with a security score and what improves it; history with filters and JSON/PDF export; scheduled
  scans; onboarding; dark theme; English, Uzbek and Russian.
- Signed signature, domain and YARA rule updates from the backend every 6 hours.
- Opt-in crash reports (off by default): app and Android version and stack frames only.
- Release hardening: R8, no logging, HTTPS only, deep-link extras accepted only from the app's own notifications,
  warning screen for modified copies, native code built with stack protector, FORTIFY and full RELRO.

### Backend

- Signature, domain and YARA ruleset distribution (`/v1/signatures`, `/v1/domains`, `/v1/rules`) with API keys and
  rate limits.
- Feed ingestion from MalwareBazaar, URLhaus and PhishTank.
- Crash report intake with 90-day retention.
- Prometheus metrics, liveness and readiness probes, JSON logs without client data.
- Production Docker Compose with Nginx, internal networks and nightly backups.

### Security

- Fixed undefined behaviour in libyara found by fuzzing and UBSan (DEX ULEB128 decoding, misaligned map list read,
  callbacks called through incompatible function pointer types); patches applied at build time
  (`cmake/patch-libyara.cmake`).
- A crafted APK manifest could stop a full scan or crash real-time protection (out-of-bounds read in the string pool
  parser, found by fuzzing); malformed manifests are now always reported as unreadable instead.
- The launcher activity no longer accepts deep-link extras from other apps (another app could make it show a forged
  scan result).

[Unreleased]: https://github.com/OWNER/BlackShield/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/OWNER/BlackShield/releases/tag/v1.0.0
