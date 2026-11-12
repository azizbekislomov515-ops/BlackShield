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
 ├── :feature:webshield ──┼──► :core:network   Retrofit ──── HTTPS ────►  FastAPI
 └── :feature:settings ───┴──► :core:data      Room, DataStore            SQLAlchemy 2 + Alembic
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

- C++17, built with CMake through the NDK for `arm64-v8a`, `armeabi-v7a` and `x86_64`. No dependencies beyond the NDK.
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
- Signature format, update mechanism and the scan pipeline built on these primitives: _TBD_.

### 3.4 Installed-app scan (`InstalledAppScanner`, `:core:scanner`)

- `PackageManagerAppSource` lists every package. This needs `QUERY_ALL_PACKAGES`; see
  [permissions.md](permissions.md).
- **For each app:**
  - The base and split APKs are hashed. SHA-256 is always computed; MD5 and SHA-1 only if the store holds
    signatures of that type.
  - All digests are looked up in one batch (`SignatureRepository.findMatches`).
  - `RiskAssessor` turns the evidence into a verdict:
    - **MALICIOUS** on any signature match. This applies even to allow-listed apps.
    - **SUSPICIOUS** at 50+ heuristic points: sideloaded +25, SMS +20, installs packages +15, overlay +15,
      debuggable +10.
    - **CLEAN** otherwise.
    - Heuristics apply only to user-installed apps that are not allow-listed.
- **Execution:** `ScanControl` handles pause and resume, and cancelling the collecting coroutine stops the scan.
  Workers run on a fixed pool of background-priority threads.
- **Persistence:** each result is saved as it completes (one row per package). After a complete scan, results for
  uninstalled apps are removed.
- **Test signatures:** debug builds seed test signatures (`app/src/debug/.../BuildTypeSignatures.kt`). These are the
  EICAR test file and the SHA-256 of the harmless `:testing:eicar-apk`, computed at build time. Install that APK to
  see a MALICIOUS verdict end to end.

### 3.5 Background work

- WorkManager with a Hilt worker factory (`ProtectionWorker`). Schedule and constraints: _TBD_.

### 3.6 Persistence

- Room `BlackShieldDatabase` v2 (schemas exported to `core/data/schemas`; `MigrationTest` checks 1→2 against them):
  - `malware_signatures`: the hash is the primary key, backed by SQLite's automatic unique index. There are no other
    indexes.
  - `signature_algorithms`: the few algorithms in use.
  - `scan_results`: one row per package, with reasons stored as JSON.
  - `allow_list` and `quarantine`.
- Bulk signature imports stream in transactions of 20,000 rows, using multi-row `INSERT` statements. 1M rows import in
  about 22 s on an emulator; see [performance.md](performance.md).
- DataStore (Preferences): user settings.
- Encryption at rest: _TBD_.

### 3.7 Networking

- Retrofit + OkHttp + kotlinx.serialization; base URL per build type.
- Authentication, certificate pinning, retry/backoff: _TBD_.

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
| 2026-11-12 | `QUERY_ALL_PACKAGES` | Malware cannot be found with `<queries>`; allowed by Play for anti-malware apps. |
