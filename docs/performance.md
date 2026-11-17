# Performance

Measurements of the native scan primitives in `:core:scanner`. Re-run the benchmarks after changing
the hashing code and update this page.

## How to reproduce

With a device or emulator connected:

```bash
cd android
./gradlew :core:scanner:connectedNativeTest -PgtestFilter='LargeFileTest.*:HashEngineTest.CancelStops*'
./gradlew :core:scanner:connectedDebugAndroidTest
adb logcat -d -s HashThroughput:I NativeHasherLargeFile:I
```

- Native numbers come from the GoogleTest suite (`LargeFileTest`, Release build, `-O2`), printed as
  `[ THROUGHPUT ]`, `[ MEMORY ]` and `[ CANCEL ]` lines.
- Kotlin numbers come from `HashThroughputBenchmark` and `NativeHasherLargeFileTest`. They go through the full
  `NativeHasher` → JNI → C++ path in the debug test APK. The digest code is compiled with `-O2` even in Debug builds
  (see `src/main/cpp/CMakeLists.txt`), so these numbers are representative.
- Throughput is measured with the file already in the page cache, so it measures hashing, not storage.

## Results — 2026-11-12

**Device:** Android Emulator, `sdk_gphone16k_x86_64` (Android 17 / API 37.2, 16 KB pages), WHPX acceleration on
an AMD Ryzen 5 8645HS host (the guest CPU exposes SHA-NI). This is an emulator on a laptop CPU; real ARM phones will
differ, so record a physical arm64 device here before drawing product conclusions.

### Throughput (MiB/s, higher is better)

| Algorithm | Native C++ (GoogleTest, 512 MiB) | `NativeHasher` (Kotlin → JNI, 256 MiB) | `java.security.MessageDigest` (BoringSSL) |
| --- | --- | --- | --- |
| MD5 | 320 – 434 | 424 – 443 | 610 – 615 |
| SHA-1 | 347 – 386 | 390 – 397 | 1 099 – 1 170 |
| SHA-256 | 285 – 289 | 284 – 292 | 1 095 – 1 127 |

Ranges cover 2–3 runs each. JNI and the Kotlin wrapper add no measurable overhead per file; the cost is in the digest loops.

**Comparison:** for SHA-1 and SHA-256 the platform's BoringSSL is about 3–4× faster, because it uses the CPU's SHA
instructions (SHA-NI here; ARMv8 Crypto Extensions on phones). Our implementation is portable C++ with no
intrinsics. If hashing becomes a bottleneck, the options are:

1. Add SHA-NI and ARMv8 `sha256h` code paths behind runtime CPU feature detection (no new dependencies).
2. Hash through `MessageDigest` for SHA-1 and SHA-256 and keep the native engine for I/O, cancellation and future
   scan logic.

### Memory (500 MiB file)

| Path | RSS growth while hashing | Method |
| --- | --- | --- |
| Native (`HashEngine::HashFile`, 512 MiB) | 0 – 68 KiB | `VmRSS` sampled every 5 ms (~300 samples) |
| Kotlin (`NativeHasher.hashFile`, 500 MiB) | 536 – 972 KiB | `VmRSS` sampled every 5 ms in the app process |

Memory use is flat. Native growth is the single 64 KiB read buffer plus the digest state, and the Kotlin figure adds
normal ART runtime noise. The tests fail if growth exceeds 1 MiB for native code or 8 MiB for Kotlin. Either limit is
a small fraction of the 500 000 KiB file.

### Cancellation latency (requirement: < 200 ms)

| Scenario | Latency |
| --- | --- |
| Native flag set while hashing a 512 MiB file (each algorithm) | 0.13 – 0.70 ms |
| Kotlin coroutine `cancel()` until the native call has returned | 0 – 13 ms |
| `CancellationSignal.cancel()` until `HashResult.Cancelled` | 0 – 1 ms |
| Stalled pipe (writer never writes), cancel mid-poll | 23 – 24 ms |

Regular files check the flag before each 64 KiB chunk, which takes about 0.2 ms to hash. Pipes and sockets wait in
`poll()` with a 50 ms timeout, so a stalled descriptor takes at most about 50 ms to notice the flag. The pipe tests
deliberately cancel mid-poll. Timing the cancel to land exactly when a poll times out would show an unrealistically
low ~2 ms.

## Signature store (Room/SQLite) — 2026-11-12

`SignatureStoreScaleTest` (`:core:data`, instrumented) imports **1,000,000 SHA-256 signatures** into the production
database configuration, on the same emulator (debuggable test APK):

| Operation | Result |
| --- | --- |
| Bulk import of 1M rows (`insertAll`, 20,000 rows per transaction) | **22.1 s** (~45,000 rows/s) |
| Batch lookup of 1,000 hashes (`findMatches`, chunks of 900) | **29–38 ms** |
| Single `isKnownMalicious` lookup | ~0.39 ms (mostly coroutine and Room dispatch overhead) |
| Database file size | **189 MB** |

How the import got from 62 s to 22 s:

| Change | Import time for 1M rows |
| --- | --- |
| Room `@Insert` list, 5,000 rows per transaction, plus an index on `algorithm` | 61.6 s |
| Index on `algorithm` dropped, batches sorted by hash, 16 MiB writer page cache | 57.9 s |
| Multi-row `INSERT OR REPLACE` (150 rows per statement, `MultiRowSignatureWriter`) | **22.1 s** |

Profiling 200k rows showed the per-statement overhead of the framework SQLite API dominates: about 46 µs per row,
almost the same for Room's generated insert and a hand-written prepared statement. Binding 150 rows per statement
brought that to about 14 µs per row.

**Known limitation, size:** each signature stores its 64-character hex hash twice, once in the table and once in the
primary-key index, so 1M rows take about 190 MB. The planned fixes, before shipping a large feed, are binary hash keys
(32 bytes) in a `WITHOUT ROWID` table, which roughly halves the size, or a prefix filter in front of SQLite.

## Installed-app scan — 2026-11-12

**262 installed packages** on the emulator (system apps plus the test APKs), 2 parallel workers on the 4-vCPU
emulator (`ScannerModule.PARALLELISM` = half the cores, at most 4):

| Build | Scan time |
| --- | --- |
| Debug, hashing on `Dispatchers.IO` (first version) | 25.2 s |
| Debug, background-priority scan pool | 9.8 – 11.2 s |
| Benchmark (R8, not debuggable) | 10.0 – 12.0 s |

Responsiveness was measured with `dumpsys gfxinfo` on the `benchmark` build type. That's the release configuration
signed with the debug key; debuggable builds render several times slower and are not representative. The emulator
renders on the CPU (SwiftShader), so "slow issue draw commands" are high even when idle. Compare the scan rows against
the idle-scroll baseline:

| Scenario | Frames | p50 | p90 | p99 | Slow UI-thread frames |
| --- | --- | --- | --- | --- | --- |
| Watching a scan (2 runs) | 96–108 | 13–17 ms | 17–28 ms | 21–97 ms | 0–8 |
| Idle scrolling, no scan (baseline) | 186 | 17 ms | 36 ms | 101 ms | 8 |
| Scrolling during a scan | 212 | 22 ms | 44 ms | 53 ms | 18 |

What keeps the UI responsive:

- Hashing runs on a fixed pool of `THREAD_PRIORITY_BACKGROUND` threads.
- Sorting the result list happens on `Dispatchers.Default`.
- During a scan, list updates are throttled to about 3 per second and progress updates to 10 per second.
- The `core:data` models are declared stable for Compose (`config/compose/stability.conf`).

**Still to do:** repeat these measurements on a physical mid-range arm64 phone, and add a Macrobenchmark for frame
timing once a `:benchmark` module exists.

## YARA

Measured 2026-11-14 on the x86_64 emulator (API 37). Reproduce with `./gradlew :core:scanner:connectedNativeTest`
(the `[ perf ]` line) and `./gradlew :core:scanner:connectedDebugAndroidTest` (logcat tag `YaraOnDeviceTest`).

**Binary size** of the stripped `libblackshield_scanner.so` (release), before and after adding libyara with the `dex`
and `math` modules:

| ABI | Before | After | Growth |
| --- | --- | --- | --- |
| arm64-v8a | 87,120 B | 313,504 B | +226 KB |
| armeabi-v7a | 51,220 B | 224,540 B | +173 KB |
| x86_64 | 83,080 B | 335,848 B | +253 KB |

Kept down by compiling only two of libyara's modules, `-ffunction-sections`/`--gc-sections`, hidden visibility and
`--exclude-libs,ALL`. In a per-ABI download from Play, users get one row, about +0.1 MB compressed.

**Scan time** with the bundled ruleset:

| Input | Time |
| --- | --- |
| 32 MiB buffer (native test) | 149 ms |
| 50 MiB APK: 17 MiB of DEX in 8 entries plus 45 MiB of stored assets | 487 ms |
| Largest APK on the device: Google app, 353 MiB with 110 MiB of DEX | 3.0–5.0 s |
| Real-time scan of a newly installed test app (hash, analysis, YARA, verdict) | 535 ms |

Each libyara call has a 10 s timeout. An expired timeout is reported as an incomplete analysis rather than a clean
result. The acceptance target (a typical 50 MB APK in a few seconds) is met with a wide margin.

**Still to do:** measure on a physical mid-range arm64 phone.

## Web Shield

Measured 2026-11-14 on the x86_64 emulator (API 37).

| What | Result |
| --- | --- |
| Matcher lookup, 200,000 listed domains (JVM unit test) | well under 50 µs per lookup (the test's bound), with one String per domain |
| Blocked lookup (`ping` of a listed subdomain) | answered from the device, without contacting any resolver |
| Wi-Fi off → mobile data, and back (`WebShieldTest`) | lookups work again within about 1 s each time; blocking keeps working |

Idle cost: none. The interface thread sleeps in `poll()`, and counters are written only after a block.

**Still to do:** measure lookup latency (forwarded vs direct) on a physical phone, and battery over a day of
normal browsing.

## Release build (R8) — 2026-11-14

`benchmark` variant (release configuration: R8, not debuggable, debug-signed) on the `blackshield_api37` emulator
(x86_64, Android 17 preview image, host Windows 11). Emulator numbers: compare releases with each other, not with
phones. Reproduce with `./gradlew :app:assembleBenchmark`, then the `adb` commands below.

| Measure | Result | How |
| --- | --- | --- |
| APK size | 3.1 MB (debug: 17 MB) | `app-benchmark.apk`, 3 ABIs |
| Cold start (after `am force-stop`) | 442–1005 ms (3 runs, median 752 ms) | `am start -W`, `TotalTime` |
| Full scan, 261 installed apps | ≈ 25 s (upper bound: includes UI polling) | Tap "Scan now" until "Scan again" |
| Memory, home screen | 42 MB PSS | `dumpsys meminfo` |
| Memory, peak during full scan | 61 MB PSS (Java heap 14 MB, native heap 24 MB after the scan) | `dumpsys meminfo` sampled ~1/s |
| Real-time protection idle, screen off | 20 ms CPU in 120 s (≈ 0.02 % of one core) | `/proc/<pid>/stat` utime + stime |
| Wake locks, 7.5 min with protection on and one scan | Only WorkManager's job lock: 18 ms (signature sync, 4 runs) | `dumpsys batterystats --charged` |
| Alarms / wakeups by the app | None | `dumpsys batterystats` |

Battery: the emulator's power profile reports 0 mAh, so energy is judged by CPU time and wakeups above. The
protection service holds no wake lock and wakes the CPU only for package broadcasts and WorkManager jobs (sync every
6 h, the scheduled scan with its charging/idle constraints). On a phone, check with Battery Historian
(`adb bugreport`) over a day with protection on; the release checklist ([release.md](release.md)) includes Android
vitals.
