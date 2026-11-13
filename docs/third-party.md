# Third-party code and content

What BlackShield ships that it did not write, under which license, and how each license's
conditions are met. Update this file in the same change that adds, upgrades or removes a dependency
or a rule source.

## Native code in the APK

| Component | Version | License | Where | Notes |
|---|---|---|---|---|
| [libyara](https://github.com/VirusTotal/yara) | 4.5.8 | BSD-3-Clause | `libblackshield_scanner.so` (statically linked) | Fetched by CMake from the release tarball, pinned by SHA-256 (`android/core/scanner/src/main/cpp/cmake/libyara.cmake`). Only the core plus the `dex` and `math` modules are compiled; no source is modified. |
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

## Android and JVM libraries

Kotlin, AndroidX (including Compose, Room, WorkManager, DataStore, Hilt), Dagger, Retrofit, OkHttp,
kotlinx.serialization, kotlinx.coroutines and Timber are Apache-2.0. Their notices are covered by the
standard Android open-source-licenses practice; see `android/gradle/libs.versions.toml` for versions.
