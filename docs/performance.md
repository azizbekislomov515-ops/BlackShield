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
