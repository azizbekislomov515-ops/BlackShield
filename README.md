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

Install on a device or emulator with `./gradlew installDebug`. The launch screen shows the result of a JNI call into
the native scanner, e.g. `pong from native scanner (C++17, arm64-v8a)`.

### Modules

| Module | Purpose |
| --- | --- |
| `:app` | Application shell: Hilt, Timber, WorkManager factory, Material 3 theme |
| `:core:scanner` | Native scan engine (C++17 via CMake/NDK, JNI) |
| `:core:data` | Room database and DataStore preferences |
| `:core:network` | Retrofit + OkHttp + kotlinx.serialization client for the backend |
| `:feature:scan` | Scan screen (currently shows the native ping) |
| `:feature:protection` | Background protection worker (WorkManager) |
| `:feature:webshield` | Web protection (placeholder) |
| `:feature:settings` | User settings |

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
| `android.yml` | `assembleDebug`, `testDebugUnitTest`, `lint`, `detekt`, `ktlintCheck` |
| `backend.yml` | `ruff check`, `ruff format --check`, `pytest`, and a `docker compose up` smoke test of `/health` |

Each workflow runs only when files under its project directory (or the workflow itself) change.
