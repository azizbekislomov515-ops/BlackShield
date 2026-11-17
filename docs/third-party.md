# Third-party code and content

What BlackShield ships that it did not write, under which license, and how each license's
conditions are met. Update this file in the same change that adds, upgrades or removes a dependency
or a rule source.

## Native code in the APK

| Component | Version | License | Where | Notes |
|---|---|---|---|---|
| [libyara](https://github.com/VirusTotal/yara) | 4.5.8 | BSD-3-Clause | `libblackshield_scanner.so` (statically linked) | Fetched by CMake from the release tarball, pinned by SHA-256 (`android/core/scanner/src/main/cpp/cmake/libyara.cmake`). Only the core plus the `dex` and `math` modules are compiled. Three fixes for undefined behaviour found by fuzzing and sanitizers are applied at configure time (`cmake/patch-libyara.cmake`); BSD-3-Clause permits modified redistribution with the notice kept. |
| LLVM libc++ (`c++_static`) | NDK 30 | Apache-2.0 WITH LLVM-exception | `libblackshield_scanner.so` | Part of the NDK toolchain. The exception waives notice requirements for compiled binaries. |

**BSD-3-Clause conditions for libyara.** Clause 2 asks binary redistributions to reproduce the
copyright notice, conditions and disclaimer "in the documentation and/or other materials provided
with the distribution". The full text ships inside the APK at `assets/licenses/libyara.txt` (from
`android/core/scanner/src/main/assets/licenses/`), copied verbatim from the release's `COPYING`.
Clause 3: the YARA name is used only to describe what the engine is, never to endorse BlackShield.
When upgrading libyara, refresh that file from the new release.

## Test-only code (not distributed)

| Component | License | Use |
|---|---|---|
| GoogleTest (from the NDK, `sources/third_party/googletest`) | BSD-3-Clause | Native unit tests (`connectedNativeTest`); linked only into the test executable, never into the APK. |
| JUnit, kotlinx-coroutines-test, OkHttp MockWebServer, AndroidX Test | EPL-1.0 / Apache-2.0 | JVM and instrumented tests. |
| Compose UI Test, Accessibility Test Framework, Espresso, AndroidX Test Services | Apache-2.0 | Compose UI tests with accessibility checks, screenshot output. |
| [Jazzer](https://github.com/CodeIntelligenceTesting/jazzer), JUnit 5 | Apache-2.0, EPL-2.0 | JVM fuzz tests of the APK, manifest and certificate parsers. |
| libFuzzer, AddressSanitizer, UndefinedBehaviorSanitizer runtimes (NDK) | Apache-2.0 WITH LLVM-exception | Native fuzzing and sanitizer test builds; never in the APK. |

## YARA rules

| Ruleset | Author | License | Where |
|---|---|---|---|
| Bundled rules | BlackShield project | Same as BlackShield | `android/core/scanner/src/main/assets/yara/bundled.yar` |
| Rules served by `GET /v1/rules` | Whoever publishes with `blackshield-signatures rules-publish` | Must be distributable (see below) | Backend database, signed per version |

The bundled rules were written for BlackShield from public descriptions of Android malware
behaviour (API names and command strings); no third-party rule text was copied. They include a
harmless test rule (`BlackShield_Test_File`), which works like the EICAR test file.

**Before publishing third-party rules to the backend**, check that their license allows
redistribution in a commercial product and record them in the table above. As a rule of thumb:

- Acceptable: MIT, BSD, Apache-2.0, CC0, and CC-BY-4.0 (keep the `author`/`reference` meta fields,
  which the attribution requires).
- Not acceptable: GPL/AGPL rules (copyleft would extend to the ruleset we distribute), the Detection
  Rule License (DRL) unless its attribution terms are met, and anything "non-commercial" (for
  example CC-BY-NC, or the Elastic License for some vendor rules).
- Rules with no license at all are not licensed for redistribution: ask the author or leave them out.

## Web Shield domain feeds (backend)

| Feed | License / terms | Use |
| --- | --- | --- |
| [URLhaus](https://urlhaus.abuse.ch/) online hosts file | CC0 1.0; abuse.ch fair use | Default malware-domain source (`domains-ingest`). |
| [PhishTank](https://phishtank.org/) `online-valid.json` | Free with an application key; attribution requested; check the current terms of use (rate limits, commercial use) before shipping | Optional phishing source (`domains-ingest --phishtank`, `PHISHTANK_APP_KEY`). |

Feeds that forbid commercial use (for example OpenPhish's community feed) are not ingested. Local feeds imported
with `domains-import` must meet the same bar as YARA rules above.

## Android and JVM libraries

| Component | License | Use |
| --- | --- | --- |
| [Tink](https://github.com/tink-crypto/tink-java) (`tink-android`) | Apache-2.0 | Quarantine encryption (streaming AEAD) and its Keystore-wrapped keyset. |
| [Material Symbols](https://github.com/google/material-design-icons) | Apache-2.0 | Icons in `core/designsystem/src/main/res/drawable/bs_ic_*.xml`, converted to vector drawables. |

Kotlin, AndroidX (including Compose, Room, WorkManager, DataStore, Hilt), Dagger, Retrofit, OkHttp,
kotlinx.serialization, kotlinx.coroutines and Timber are Apache-2.0. Their notices are covered by the
standard Android open-source-licenses practice; see `android/gradle/libs.versions.toml` for versions.

## Backend and deployment

| Component | License | Use |
| --- | --- | --- |
| FastAPI, Pydantic, SQLAlchemy, Alembic (MIT); Starlette, Uvicorn, httpx2 (BSD-3-Clause); cryptography (Apache-2.0 OR BSD-3-Clause); psycopg (LGPL-3.0-only, used unmodified as a library) | as listed | API server (versions pinned in `backend/pyproject.toml`) |
| [prometheus-client](https://github.com/prometheus/client_python) | Apache-2.0 AND BSD-2-Clause | `/metrics` |
| [Nginx](https://nginx.org/) (`nginx:1.28-alpine` image) | BSD-2-Clause | Reverse proxy in `docker-compose.prod.yml` |
| [PostgreSQL](https://www.postgresql.org/) (`postgres:18-alpine` image) | PostgreSQL License | Database |
| pip-audit, pytest, Ruff | Apache-2.0, MIT | Development and CI only |
