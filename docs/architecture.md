# BlackShield architecture

> Status: skeleton. Sections marked _TBD_ are to be filled in as the design is decided.

## 1. Overview

BlackShield is an Android security app (on-device scanning, background protection, web protection) backed by an
HTTP API.

```
Android app                                              backend
-----------                                              -------
:app
 ├── :feature:scan ───────┐
 ├── :feature:protection ─┼──► :core:scanner   Kotlin ⇄ JNI ⇄ C++17
 ├── :feature:webshield ──┤
 └── :feature:settings ───┼──► :core:sync      WorkManager, sync engine
                          ├──► :core:network   Retrofit ──── HTTPS ────►  FastAPI
                          └──► :core:data      Room, DataStore            SQLAlchemy 2 + Alembic
                                                                          PostgreSQL
```

## 2. Goals and non-goals

- Goals: _TBD_
- Non-goals: _TBD_

## 3. Android app

### 3.1 Module structure and dependency rules

- `:app` depends on feature and core modules and wires them together. It holds no business logic.
- `:feature:*` modules depend only on `:core:*` modules, never on each other.
- `:core:*` modules do not depend on features.
- Shared Gradle configuration lives in `build-logic` convention plugins; versions live in `gradle/libs.versions.toml`.

### 3.2 Layers

- UI: Jetpack Compose (Material 3) screens that render an immutable `UiState` exposed by a `ViewModel` as a `StateFlow`.
- Domain: _TBD_ (use cases, if and when they are needed).
- Data: repositories over Room, DataStore and the network API.
- Dependency injection: Hilt across all modules; KSP for code generation.

### 3.3 Native scan engine (`:core:scanner`)

- C++17, built with CMake through the NDK for `arm64-v8a`, `armeabi-v7a` and `x86_64`. One third-party dependency:
  libyara (see 3.9 and [third-party.md](third-party.md)).
- `blackshield_scanner_core` (static, no JNI): the scan primitives. `libblackshield_scanner.so` adds the JNI layer.
- **Hashing:** `HashEngine` streams a file path or file descriptor through MD5, SHA-1 or SHA-256 (own implementations)
  in 64 KiB chunks, so memory use does not depend on file size.
  - Seekable files are hashed with `pread()` from offset 0, leaving the caller's descriptor offset unchanged.
  - Pipes and sockets are `poll()`ed with a 50 ms timeout, so cancellation can't get stuck on a blocked read.
  - Every outcome is a status code (ok, not found, permission denied, cancelled, I/O error, invalid argument, internal
    error) plus errno. Nothing throws across the JNI boundary.
- **JNI rules** (`hash_jni.cpp`):
  - Every argument is validated, and paths are converted from UTF-16 to real UTF-8 (not JNI's modified UTF-8).
  - All C++ exceptions are caught, and no Java exception is left pending.
  - Cancellation tokens are opaque ids looked up in a registry, so a stale or forged token can never be dereferenced.
- **Kotlin API:**
  - `NativeHasher.hashFile` and `NativeHasher.hashFd(ParcelFileDescriptor)` are suspend functions that run on
    `Dispatchers.IO` and return a sealed `HashResult`.
  - Coroutine cancellation sets the native flag and rethrows; an optional `CancellationSignal` returns
    `HashResult.Cancelled`.
- Tests: GoogleTest on the device (`connectedNativeTest`), instrumented tests and a throughput benchmark. Measured
  figures are in [performance.md](performance.md).
- Signature format and sync: [sync-protocol.md](sync-protocol.md). Pattern matching: 3.9.

### 3.4 Installed-app scan (`InstalledAppScanner`, `:core:scanner`)

- `PackageManagerAppSource` lists every package. This needs `QUERY_ALL_PACKAGES`; see
  [permissions.md](permissions.md).
- **For each app:**
  - The base and split APKs are hashed. SHA-256 is always computed; MD5 and SHA-1 only if the store holds
    signatures of that type.
  - All digests are looked up in one batch (`SignatureRepository.findMatches`).
  - `ApkAnalyzer` extracts an `AppProfile` (permissions, components with intent filters from the binary manifest,
    signing certificates, installer, launcher state, packer traces). See [risk-rules.md](risk-rules.md).
  - `RiskAssessor` turns the evidence into a verdict:
    - **MALICIOUS** on any signature match. This applies even to allow-listed apps.
    - Otherwise `RiskEngine` scores the profile with JSON rules (`assets/risk/risk_rules.json`): 40+ is
      SUSPICIOUS, 75+ MALICIOUS. Every point comes with a plain-language reason and its evidence.
    - System apps and apps the user trusts are not scored.
- **Execution:** `ScanControl` handles pause and resume, and cancelling the collecting coroutine stops the scan.
  Workers run on a fixed pool of background-priority threads.
- **Persistence:** each result is saved as it completes (one row per package). After a complete scan, results for
  uninstalled apps are removed.
- **Test signatures:** debug builds seed test signatures (`app/src/debug/.../BuildTypeSignatures.kt`). These are the
  EICAR test file and the SHA-256 of the harmless `:testing:eicar-apk`, computed at build time. Install that APK to
  see a MALICIOUS verdict end to end.

### 3.5 Background work

- WorkManager with a Hilt worker factory, owned by `:app` (`AppModule` provides `WorkManager`).
- Real-time protection is a foreground service, not WorkManager (see 3.8).
- `SignatureSyncWorker` (`:core:sync`), scheduled by `SignatureSyncScheduler` from `BlackShieldApplication`:
  - periodic, every 6 hours, battery and storage not low, on an unmetered network when the user's *Update over
    Wi-Fi only* setting is on (default off), otherwise any network. A setting change re-enqueues with
    `ExistingPeriodicWorkPolicy.UPDATE`, which keeps the current period;
  - an initial one-time sync when the app starts and has never synced, following the same network setting;
  - *Sync now* from Settings: one-time, any network.
  - One-time requests are expedited on Android 12+ (before 12, expedited work needs a foreground-service
    notification, so it runs as regular work). Retryable failures back off exponentially from 30 s, up to 5
    attempts; authentication and certificate failures are not retried until the next period.
  - The algorithm and its consistency guarantees are in [sync-protocol.md](sync-protocol.md#4-android-client).

### 3.6 Persistence

- Room `BlackShieldDatabase` v2 (schemas exported to `core/data/schemas`; `MigrationTest` checks 1→2 against them):
  - `malware_signatures`: the hash is the primary key, backed by SQLite's automatic unique index. There are no other
    indexes.
  - `signature_algorithms`: the few algorithms in use.
  - `scan_results`: one row per package, with reasons stored as JSON.
  - `allow_list` and `quarantine`.
- Bulk signature imports stream in transactions of 20,000 rows, using multi-row `INSERT` statements. 1M rows import in
  about 22 s on an emulator; see [performance.md](performance.md).
- Signature sync writes through `SignatureSyncStore`: one transaction per delta or snapshot. Synced rows have
  `source = 'blackshield-cloud'`; rows from other sources (debug seeds) are never deleted by sync.
- DataStore (Preferences): user settings (`user_preferences`) and sync state (`signature_sync`: version, last
  success and attempt, last error). A corrupted sync-state file is replaced by an empty one, which forces a full
  snapshot.
- Encryption at rest: _TBD_.

### 3.7 Networking

- Retrofit + OkHttp + kotlinx.serialization (`BlackShieldHttp`), configured by `NetworkConfig` from Gradle properties
  (see the README): base URL, API key and certificate pins. Nothing secret is committed.
- Auth: `X-API-Key` on requests to the configured backend origin only; redirects are not followed.
- Certificate pinning: OkHttp `CertificatePinner` with `host=sha256/…` pins; empty disables it (debug). Release HTTPS
  only (`network_security_config.xml`); debug builds also allow cleartext to the emulator host (10.0.2.2) and
  localhost.
- Timeouts: connect 15 s, read 30 s (between reads, so a large snapshot can stream), write 15 s, no call timeout.
- gzip: transparent for JSON. The snapshot is requested with an explicit `Accept-Encoding: gzip`, so it arrives
  compressed and is staged on disk as received.
- Retries and backoff are WorkManager's (see 3.5), not OkHttp interceptors.

### 3.8 Real-time protection (`:feature:protection`)

- **`RealtimeProtectionService`**, a foreground service of type `specialUse` with a low-importance status
  notification ("Turn off" action):
  - **Why a service:** since Android 8, `PACKAGE_ADDED` / `PACKAGE_REPLACED` reach only receivers registered at
    runtime in a running process.
  - **Why `specialUse`:** `dataSync` is capped at 6 h a day and is blocked from `BOOT_COMPLETED` on Android 15+.
  - **Lifetime:** not `stopWithTask`, so it survives swipe-away, and it is `START_STICKY`.
  - **Restarts:** `ProtectionBootReceiver` (`BOOT_COMPLETED`, `MY_PACKAGE_REPLACED`, both exempt from the background
    FGS start restrictions) restores it after a reboot or update. `MainActivity` keeps it in line with the setting
    while visible.
  - **Catch-up:** installs missed while it was not running are found with `PackageManager.getChangedPackages()`.
    The cursor is stored with the boot count, because sequence numbers restart at boot.
- **Install path:** dynamic receiver → `ProtectionEngine`, which debounces each package for 300 ms (an update sends
  ADDED + REPLACED) → `InstalledAppScanner.scanPackage()` → result saved → `AlertPolicy` → high-importance warning with
  Uninstall (system `ACTION_DELETE` dialog), Ignore (by APK SHA-256) and Details. Measured on the emulator: the
  warning appears 0.4–0.9 s after an install finishes.
- **Files:** `ApkFileScanner` scans APKs before installation. Content URIs are copied to a private cache file;
  archives are parsed with `getPackageArchiveInfo` plus the manifest parser, and `AppProfile.isArchive` makes the
  source count as "downloaded file". Watchers, chosen by `WatchPlanner`:
  - **Download, Android 11+:** MediaStore observer with a `GENERATION_MODIFIED` cursor; needs All files access.
    Pending rows are included, because files written straight through FUSE can stay pending.
  - **Download, Android 10 and older:** `FileObserver` (`CLOSE_WRITE` / `MOVED_TO`); needs `READ_EXTERNAL_STORAGE`.
  - **User-picked folders:** Storage Access Framework trees, observed through the provider's notification URI while
    a cursor stays open. No permission needed.
  - File events are debounced for 1.5 s and deduplicated by path, size and modification time. There is no polling
    anywhere.
- **Alerts for files** carry the result in the Details intent (`FileResultCodec`), since a file has no stored
  result. They have no Uninstall action: the file is not installed.
- **Troubleshooting screen:** `DeviceHealthReader` takes a snapshot (notifications and threat channel, battery
  optimization, background restriction, standby bucket, storage access, manufacturer), and the pure
  `TroubleshootingChecks` ranks the issues, each with a fix that opens the right system or vendor screen.
- **Permissions:** see [permissions.md](permissions.md#real-time-protection), including why All files access is
  the only way to watch Downloads on Android 11+.
- **Known limits:**
  - Files written straight through the file system by some apps (e.g. `adb`) can stay pending in MediaStore and are
    never announced. Such an APK is still scanned when it is installed.
  - Folder watching covers the top level of a picked folder only.
  - Some vendor task killers can stop any service; the troubleshooting screen guides the user.

### 3.9 YARA pattern matching (`:core:scanner`)

- **libyara 4.5.8** (BSD-3-Clause), fetched by CMake `FetchContent` from the release tarball and pinned by SHA-256
  (`src/main/cpp/cmake/libyara.cmake`). libyara has no CMake build, so that file lists its sources and the flags its
  autotools build would use. Only the `dex` and `math` modules are compiled in (`cmake/yara-modules/modules/module_list`
  replaces upstream's list); process scanning is off. Offline builds pass `-DFETCHCONTENT_SOURCE_DIR_LIBYARA=<dir>`.
  Cost: about +230 KB per ABI in the stripped `.so` ([performance.md](performance.md#yara)).
- **C++ `YaraScanner`** (`src/main/cpp/yara/`):
  - `Compile(source)` compiles once; identical sources share one compiled ruleset (weak cache keyed by SHA-256).
    `include` is disabled: rules arrive as one signed file and must never read other files.
  - The compiled scanner is immutable. Each scan creates its own libyara scanner, so scans run in parallel.
  - `ScanFile`/`ScanMemory` take a timeout in milliseconds. libyara's public API only takes whole seconds, so the
    nanosecond field is set directly. libyara checks it every 4 KiB of input and every 100 condition instructions.
  - Results: rule, namespace, tags, metadata, capped at 256 matches. Every failure is a status code (ok, timeout,
    compile error, file error, invalid argument, internal); nothing throws across JNI.
- **JNI** (`yara_jni.cpp`): compiled rulesets are opaque handles in a registry, the same way as cancellation tokens.
  Rule source goes in as UTF-8 bytes. Matches come back as a flat `String[]`, so no app classes are looked up from
  native code. Strings from rules are decoded leniently (invalid UTF-8 becomes U+FFFD): `NewStringUTF` would abort
  the VM under CheckJNI.
- **Kotlin** (`yara/`):
  - `YaraScanner.scan(file)` scans the file as it is on disk.
  - For APKs, it also streams each `*.dex` entry out of the ZIP into one reused direct `ByteBuffer`
    (`DexEntries`), because DEX code is stored compressed. Nothing is extracted to disk.
  - Sizes come from the central directory and are enforced while inflating, which stops zip bombs. Limits: 64 MiB
    per DEX, 64 DEX files, 10 s per libyara call.
  - Handles are reference-counted, so replacing the rules never frees them under a running scan.
- **Rules lifecycle** (`YaraRules`):
  - The bundled ruleset (`assets/yara/bundled.yar`, versioned by its header) or a newer signed update from
    `GET /v1/rules`, stored in `noBackupFilesDir/yara/ruleset.json`.
  - Updates are ECDSA P-256 signed offline. `RulesetVerifier` checks key id, signature, digest and version on
    arrival and again on every load, so a file edited on disk is rejected, deleted, and the bundled rules are used.
  - An update must be newer than the active and bundled rules (no rollback) and must compile before it replaces them.
  - Trusted public keys come from the Gradle property `blackshield.yaraRulesPublicKeys`. With none configured, no
    update is accepted.
  - `YaraRulesSyncEngine` (`:core:sync`) runs after the signature sync in the same worker, with `If-None-Match`. A new
    ruleset applies to the next scan, with no app update or restart.
- **Scoring:** `InstalledAppScanner` and `ApkFileScanner` add matches to `AppProfile.yaraMatches`. The risk rules
  `yara_critical` (+100), `yara_high` (+50), `yara_medium` (+25) and `yara_low` (+10) score them by the rule's
  `severity` meta. YARA is skipped for system apps (exempt), apps the user trusts, and known-malware matches. Timeouts
  and unreadable entries are reported as `ANALYSIS_INCOMPLETE`.

### 3.10 Web Shield (`:feature:webshield`)

An on-device DNS filter built on `VpnService`.

- **Routing.** The VPN routes only the virtual DNS server it advertises (`10.111.222.2`, `fd00:b1a5:5e1d::2`), so
  only DNS enters it. BlackShield itself is excluded. Nothing is sent to a remote VPN server.
- **Packet path.** `TunLoop` → `IpPackets` (IPv4/IPv6 + UDP, checksums) → `DnsPacketHandler` → `DnsFilter`.
  - `TunLoop` reads the non-blocking interface on one thread that sleeps in `poll()`; a pipe wakes it to stop.
  - `DnsMessages` parses only the question (compression pointers, loop and length limits).
  - Blocked names get NXDOMAIN without an SOA, so the answer is not cached and "Allow once" works on the next
    lookup. A sinkhole mode exists.
  - Allowed queries go byte for byte through `DnsForwarder`: one socket per query, bound to the real network and
    protected. Answer ids are checked, and servers are tried in order with a 2 s timeout.
- **Real network.** `UpstreamTracker` follows the best non-VPN internet network (`registerBestMatchingNetworkCallback`
  / `requestNetwork`). The default-network callback reports our own VPN even though the app is excluded.
  - On a Wi-Fi/mobile switch the next query uses the new network's resolvers, and `setUnderlyingNetworks` keeps
    transport and metering right.
  - Private DNS in strict mode is detected and shown as a warning.
- **Matching.** `DomainMatcher` is a label trie stored flat: reversed-label keys in a sorted array, one binary
  search per label of the query, with subdomain matching. The user allowlist and temporary "Allow once" allowances
  win over the blocklist. The matcher is rebuilt when the Room table changes; the domain sync is in
  [sync-protocol.md](sync-protocol.md) section 8.
- **Lifecycle.**
  - `WebShieldController` asks for the VPN permission through the UI, after an explanation dialog.
  - `onRevoke` (another VPN, or disconnected in settings) turns the setting off and notifies the user.
  - The system can start the service as the always-on VPN. A boot receiver restarts it if it was on.
  - State for the screen and the quick settings tile is a `StateFlow` in `WebShieldRuntime`.
- **Privacy.** No domain is logged. Counters are aggregates, and the opt-in activity log keeps blocked lookups only,
  for 7 days.

## 4. Backend

- FastAPI application factory (`app/main.py`), routers in `app/api/`.
- Settings via pydantic-settings (environment variables / `.env`).
- SQLAlchemy 2 ORM; Alembic migrations run on container start.
- Health: `/health` (liveness) and `/health/ready` (database reachability).
- API surface, authentication and data model: _TBD_.

## 5. Security and privacy

- App backups are disabled (`allowBackup=false`, empty data-extraction rules).
- Threat model: _TBD_
- Data collected and retention: _TBD_

## 6. Build, CI and release

- CI: GitHub Actions (`.github/workflows/android.yml`, `.github/workflows/backend.yml`).
- Android quality gates: strict lint, detekt, ktlint, unit tests.
- Backend quality gates: ruff, pytest, docker compose smoke test.
- Release signing, versioning and distribution: _TBD_.

## 7. Decision log

| Date | Decision | Rationale |
| --- | --- | --- |
| 2026-11-12 | Monorepo with `android/` and `backend/` | One place for app, API and CI. |
| 2026-11-12 | AGP 9 built-in Kotlin with convention plugins | Shared configuration across 8 modules. |
| 2026-11-12 | Signatures in SQLite with a hex TEXT primary key | Simple and indexed; fine to ~1M rows. Revisit (binary keys, `WITHOUT ROWID`, prefix filter) before shipping large feeds. |
| 2026-11-13 | Static analysis rules as JSON, strict schema, capability cap | Updatable from the backend; a bad file is rejected whole; capabilities alone cannot make an app malicious. |
| 2026-11-13 | Real-time protection as a `specialUse` foreground service | Package broadcasts need a running process; `dataSync` has daily limits and boot restrictions. |
| 2026-11-13 | All files access only for Downloads on Android 11+, optional | No narrower API can see other apps' APK downloads; SAF covers other folders without a permission. |
| 2026-11-13 | Own binary-manifest parser, attributes by resource ID | PackageManager hides intent filters; reading attributes like the platform defeats renamed-attribute tricks. |
| 2026-11-12 | `QUERY_ALL_PACKAGES` | Malware cannot be found with `<queries>`; allowed by Play for anti-malware apps. |
| 2026-11-13 | Download first, then one transaction (delta pages in memory, snapshot to a file) | The write transaction never waits on the network, and a killed process can only roll back. |
| 2026-11-13 | Sync version in DataStore, written after the Room commit | A crash in between leaves an older version; re-applying a delta is idempotent. |
| 2026-11-13 | Strict payload validation (unknown enum fails the sync) | Silently dropped rows would make counts disagree and force a snapshot on every sync. |
| 2026-11-14 | libyara via FetchContent (pinned tarball + SHA-256), own target list, `dex` + `math` only | No submodule to manage; upstream has no CMake build; unused modules (PE, ELF, .NET...) would add size for nothing. |
| 2026-11-14 | YARA updates signed with ECDSA P-256, key offline, verified on every load | Ed25519 is not in the platform before API 33; the API server never holds the key, so a compromised server cannot push rules. |
| 2026-11-14 | DEX streamed from the ZIP into memory, one entry at a time | DEX is stored compressed in most APKs; extracting would write user files to disk and cost I/O. |
| 2026-11-14 | Web Shield as a DNS-only local VPN (two /32 and /128 routes), app excluded | The only way to see lookups without a remote server; browsing traffic never enters the app. |
| 2026-11-14 | NXDOMAIN without SOA for blocked names | Works for every record type and is not cached, so "Allow once" takes effect at once. |
| 2026-11-14 | Domain delta from version 0 instead of a snapshot endpoint | Domain lists are small (tens of thousands); one protocol, no NDJSON stream to maintain. |
| 2026-11-14 | Never-block list on the backend | DNS blocks whole hosts; phishing on shared platforms must not take down Google Docs or GitHub Pages. |
| 2026-11-14 | YARA matches scored as risk rules (critical +100) | One explanation model for every deduction; a critical match is malicious even from Play, while system and known-good apps stay exempt. |
