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

- C++17, built with CMake through the NDK for `arm64-v8a`, `armeabi-v7a` and `x86_64`.
- Kotlin calls into C++ through JNI (`NativeScanner`); the rest of the app sees only the `ScannerEngine` interface.
- Currently exposes only `ping()` to prove the build and loading pipeline.
- Signature format, update mechanism, threading model and memory limits: _TBD_.

### 3.4 Background work

- WorkManager with a Hilt worker factory (`ProtectionWorker`). Schedule and constraints: _TBD_.

### 3.5 Persistence

- Room: `BlackShieldDatabase` (schemas exported to `core/data/schemas` for migration tests).
- DataStore (Preferences): user settings.
- Encryption at rest: _TBD_.

### 3.6 Networking

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
