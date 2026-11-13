# BlackShield

Monorepo for the BlackShield Android security app and its backend API.

```
.
├── android/            Gradle multi-module Android app (Kotlin, Compose, NDK)
├── backend/            FastAPI + PostgreSQL service
├── docs/               Architecture and design notes
└── .github/workflows/  CI for both projects
```

See [docs/architecture.md](docs/architecture.md) for how the pieces fit together.

## Android

### Prerequisites

| Tool | Version |
| --- | --- |
| JDK | 17 or newer (CI uses 21) |
| Android SDK | platform 37 (`compileSdk`/`targetSdk` 37, `minSdk` 26) |
| NDK | 30.0.16248370 |
| CMake | 4.1.2 (SDK package) |

Android Studio installs these on sync. From the command line, AGP downloads the pinned SDK platform, build-tools,
NDK and CMake on the first build, provided the SDK licenses are accepted. Point Gradle at your SDK with
`ANDROID_HOME` or `android/local.properties`:

```properties
sdk.dir=C\:/Users/you/AppData/Local/Android/Sdk
```

### Build and check

```bash
cd android
./gradlew assembleDebug testDebugUnitTest lint
```

```bash
./gradlew detekt ktlintCheck
```

```bash
./gradlew ktlintFormat
```

```bash
./gradlew assembleRelease
```

- `lint` is strict: every warning fails the build (rules that only flag newer library versions are off).
- `detekt` runs from the root over all modules (config: `android/config/detekt/detekt.yml`).
- `ktlint` uses the `android_studio` code style configured in `.editorconfig`; `ktlintFormat` fixes most findings.
- `assembleRelease` runs R8 (code and resource shrinking); the APK is unsigned until a signing config is added.

Tests that need a connected device or emulator (`adb devices` must list one):

```bash
./gradlew :core:scanner:connectedNativeTest
```

```bash
./gradlew :core:scanner:connectedDebugAndroidTest
```

- `connectedNativeTest` builds the C++ GoogleTest suite (`core/scanner/src/nativeTest/cpp`) with the NDK, then pushes
  it to the device and runs it. Optional flags: `-PnativeTestAbi=arm64-v8a`, `-PgtestFilter='Sha*'`.
- `connectedDebugAndroidTest` runs the instrumented Kotlin tests, including 500 MiB memory and cancellation checks
  and the throughput benchmark (see [docs/performance.md](docs/performance.md)).

Install on a device or emulator with `./gradlew installDebug`.

**End-to-end detection check.** Debug builds treat the harmless `:testing:eicar-apk` app as malware: its SHA-256 is
seeded into the signature database at build time.

```bash
./gradlew :testing:eicar-apk:installDebug :app:installDebug
```

Open BlackShield and tap **Scan now**. *BlackShield EICAR test* should be listed as **Malicious**. Release builds seed
no signatures.

The `benchmark` build type (`./gradlew :app:installBenchmark`) is the release configuration signed with the debug
key. Use it for performance measurements. Permissions and their Play policy justification are in
[docs/permissions.md](docs/permissions.md). The launch screen shows the result of a JNI call into
the native scanner, e.g. `pong from native scanner (C++17, arm64-v8a)`.

### Backend connection (signature sync)

The app downloads malware signatures from the backend (see [docs/sync-protocol.md](docs/sync-protocol.md)). Connection
settings come from Gradle properties (`-P…` or `~/.gradle/gradle.properties`) or environment variables; nothing secret
is committed:

| Property | Environment variable | Default |
| --- | --- | --- |
| `blackshield.apiKey` | `BLACKSHIELD_API_KEY` | empty: the backend answers 401 and Settings shows the error |
| `blackshield.apiBaseUrl` | `BLACKSHIELD_API_BASE_URL` | debug `http://10.0.2.2:8000/`, release `https://api.blackshield.invalid/` |
| `blackshield.certificatePins` | `BLACKSHIELD_CERTIFICATE_PINS` | empty (no pinning); `host=sha256/…` entries, comma-separated, include a backup pin |

Against a local backend from an emulator (create the key with `blackshield-signatures generate-api-key --id android-dev`):

```bash
adb reverse tcp:8000 tcp:8000
```

```bash
BLACKSHIELD_API_KEY=bs_... BLACKSHIELD_API_BASE_URL=http://localhost:8000/ ./gradlew installDebug
```

`adb reverse` is only needed when the emulator cannot reach the host at `10.0.2.2`. Debug builds allow plain HTTP to
`10.0.2.2` and `localhost` only.

### Modules

| Module | Purpose |
| --- | --- |
| `:app` | Application shell: Hilt, Timber, WorkManager factory, Material 3 theme |
| `:core:scanner` | Native hash engine (C++17 via CMake/NDK, JNI) and the installed-app scanner |
| `:core:data` | Room database (signatures, scan results, allow-list, quarantine) and DataStore preferences |
| `:core:network` | Retrofit + OkHttp client for the backend: API key, certificate pinning, typed models, snapshot reader |
| `:core:sync` | Signature sync: engine, `SignatureSyncWorker` (WorkManager), scheduler, sync state |
| `:feature:scan` | Scan screen: Scan now, live progress, results with verdicts, details |
| `:feature:protection` | Background protection worker (WorkManager) |
| `:feature:webshield` | Web protection (placeholder) |
| `:feature:settings` | Settings: real-time protection, signature database status, Sync now, Wi-Fi-only updates |
| `:testing:eicar-apk` | Harmless test app whose hash debug builds treat as malware |

Shared build configuration lives in `android/build-logic` as convention plugins (`blackshield.android.application`,
`blackshield.android.library`, `blackshield.android.compose`, `blackshield.android.feature`, `blackshield.hilt`);
all versions are in `android/gradle/libs.versions.toml`.

## Backend

### With Docker (recommended)

```bash
cd backend
cp .env.example .env
docker compose up --build
```

```bash
curl -i http://localhost:8000/health
```

- `GET /health` is a liveness check and always returns 200 while the API is running.
- `GET /health/ready` also checks PostgreSQL and returns 503 if the database is unreachable.
- Interactive API docs: <http://localhost:8000/docs>.

The API container runs `alembic upgrade head` before starting uvicorn.

### Local development

Requires Python 3.12+ and a reachable PostgreSQL (for example `docker compose up db`).

```bash
cd backend
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env             # DATABASE_URL points at localhost
uvicorn app.main:app --reload
```

```bash
ruff check . && ruff format --check . && pytest
```

Create a migration after adding models (import them in `app/db/models.py`):

```bash
alembic revision --autogenerate -m "describe change"
alembic upgrade head
```

## Continuous integration

| Workflow | Runs |
| --- | --- |
| `android.yml` | `assembleDebug`, `testDebugUnitTest`, `lint`, `detekt`, `ktlintCheck`; native GoogleTest and instrumented tests on an emulator |
| `backend.yml` | `ruff check`, `ruff format --check`, `pytest`, and a `docker compose up` smoke test of `/health` |

Each workflow runs only when files under its project directory (or the workflow itself) change.
