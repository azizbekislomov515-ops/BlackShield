# Privacy: what BlackShield stores and sends

The engineering view of BlackShield's data handling: every piece of data, where it lives, who can see it and how long
it is kept. The user-facing text is [privacy-policy.md](privacy-policy.md); the Google Play Data safety answers are in
[play-policy-checklist.md](play-policy-checklist.md#data-safety-form). Keep all three in step with the code.

**Principle:** scanning, matching and DNS filtering happen on the phone. The backend only distributes threat data
(signatures, YARA rules, blocked domains). The single exception is crash reports, which are off until the user turns
them on.

## On the device

All of it is in app-private storage, excluded from backups (`allowBackup=false`, empty data-extraction rules), and
deleted when the app is uninstalled.

| Data | Where | Kept | Notes |
| --- | --- | --- | --- |
| Scan results (package, label, version, APK SHA-256, verdict, reasons) | Room `scan_results` | Until the app is uninstalled or the package is removed | One row per installed package |
| History (scans, checks, quarantine actions) | Room `history` | 1 year | Exportable by the user (JSON/PDF) to a place they pick |
| Detected and quarantined files | Room `file_threats`; encrypted files in `noBackupFilesDir/quarantine` | Until restored or deleted by the user | Tink AES-256-GCM, Keystore-wrapped key |
| Signatures, YARA rules, blocked domains | Room, files | Replaced by updates | Public threat data |
| Settings | DataStore | — | Including the crash-report choice |
| Web Shield counters | DataStore | — | Aggregates only (blocked count per day) |
| Web Shield activity log | Room | 7 days, **opt-in** | Blocked lookups only (domain, time); allowed lookups are never recorded |
| Pending crash reports | `noBackupFilesDir/crash-reports` | Until sent; at most 5 | Only written while crash reports are on; deleted when they are turned off |

The app writes nothing to logcat in release builds (no Timber tree; R8 strips log calls).

## Sent to the BlackShield backend

| Request | When | Contains | Does not contain |
| --- | --- | --- | --- |
| `GET /v1/signatures/*`, `/v1/rules`, `/v1/domains/*` | Every 6 h (WorkManager) and on "Sync now" | The client's current dataset version | Anything about the device, its apps or its user |
| `POST /v1/crashes` | After a crash, **only if the user turned crash reports on** | App version and code, Android SDK level, crash time, exception class names, stack frames (class, method, file, line) | Exception messages, device model, identifiers, installed apps, file names |

Every request carries the build's API key (the same for every install, so it identifies the app build, not the
user) and the user agent `BlackShield-Android`. No advertising ID, Android ID, account, IMEI or other identifier is read
or sent. The app does not call `POST /v1/reputation/lookup`, so no hashes of the user's files leave the phone.

DNS lookups that Web Shield allows go to the resolver of the network the phone is on, as they would without
BlackShield. They never go to the BlackShield backend.

## On the backend

| Data | Kept | Notes |
| --- | --- | --- |
| Access log lines (method, path, status, duration, request id, API key id) | Log retention of the host (30 days recommended) | No client IP, query string, headers or bodies (API and Nginx log formats) |
| Rate-limit buckets | In memory, minutes | Keyed by API key id and client IP; never written to disk or logs |
| Crash reports | 90 days (`crashes-prune`, daily) | The fields above plus the time received; no IP address |
| Prometheus metrics | Per the metrics store | Counts by route template, method, status; no client data in labels |

Client IP addresses are processed transiently for rate limiting (Nginx and the API) and never stored.

## Third parties

None at runtime: no analytics, advertising, crash-reporting or tracking SDKs. Threat feeds (MalwareBazaar, URLhaus,
PhishTank) are fetched by the backend; the phone never contacts them.

## Changing any of this

A change that adds data to a request, keeps data longer, or adds a third party must update this page, the privacy
policy and the Play Data safety form in the same change, and needs a privacy review.
