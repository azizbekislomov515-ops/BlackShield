package com.blackshield.core.scanner.apps

import com.blackshield.core.data.model.MalwareSignature
import com.blackshield.core.data.model.ScanReason
import com.blackshield.core.data.model.ScanResult
import com.blackshield.core.data.model.Severity
import com.blackshield.core.data.model.SignatureAlgorithm
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.data.repository.AllowListRepository
import com.blackshield.core.data.repository.ImportResult
import com.blackshield.core.data.repository.ScanResultRepository
import com.blackshield.core.data.repository.SignatureRepository
import com.blackshield.core.scanner.analysis.ApkAnalyzer
import com.blackshield.core.scanner.analysis.AppComponent
import com.blackshield.core.scanner.analysis.AppProfile
import com.blackshield.core.scanner.hash.FileHasher
import com.blackshield.core.scanner.hash.HashAlgorithm
import com.blackshield.core.scanner.hash.HashResult
import com.blackshield.core.scanner.risk.RiskRulesSource
import com.blackshield.core.scanner.risk.TestProfiles
import com.blackshield.core.scanner.risk.TestProfiles.accessibilityService
import com.blackshield.core.scanner.yara.ApkPatternScanner
import com.blackshield.core.scanner.yara.PatternScanResult
import com.blackshield.core.scanner.yara.YaraMatch
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class InstalledAppScannerTest {
    private val signatures = FakeSignatureRepository()
    private val results = FakeScanResultRepository()
    private val allowList = FakeAllowListRepository()
    private val hasher = FakeHasher()
    private val analyzer = FakeAnalyzer()
    private val patterns = FakePatternScanner()
    private val clock = Clock.fixed(Instant.ofEpochMilli(1_700_000_000_000), ZoneOffset.UTC)

    @Test
    fun `scans every app, flags matches, persists results and reports progress`() = runTest {
        signatures.add(MALWARE_SHA256, SignatureAlgorithm.SHA256, Severity.CRITICAL)
        val apps =
            listOf(
                app("com.evil", installer = "com.android.vending", base = "/evil/base.apk"),
                app("com.chrome", installer = "com.android.vending", base = "/chrome/base.apk"),
                app(
                    "com.flashlight",
                    installer = null,
                    base = "/flash/base.apk",
                    permissions = setOf("android.permission.READ_SMS", "android.permission.SYSTEM_ALERT_WINDOW")
                )
            )
        hasher.digests["/evil/base.apk" to HashAlgorithm.SHA256] = MALWARE_SHA256
        analyzer.components["com.flashlight"] = listOf(accessibilityService("com.flashlight.Watcher"))

        val progress = scanner(apps).scan().toList()

        assertEquals(ScanProgress.Started(3), progress.first())
        val scanned = progress.filterIsInstance<ScanProgress.AppScanned>()
        assertEquals(listOf(1, 2, 3), scanned.map { it.scanned }.sorted())
        assertEquals(ScanProgress.Completed(3, malicious = 1, suspicious = 1, durationMillis = 0), progress.last())

        val evil = results.saved.getValue("com.evil")
        assertEquals(Verdict.MALICIOUS, evil.verdict)
        assertEquals(100, evil.riskScore)
        assertEquals(MALWARE_SHA256, evil.apkSha256)
        assertEquals(ScanReason.Code.KNOWN_MALWARE, evil.reasons.single().code)
        assertEquals(Verdict.CLEAN, results.saved.getValue("com.chrome").verdict)
        assertEquals(Verdict.SUSPICIOUS, results.saved.getValue("com.flashlight").verdict)
        assertEquals(clock.millis(), evil.scannedAt)
    }

    @Test
    fun `split APKs are hashed and matched too`() = runTest {
        signatures.add(MALWARE_SHA256, SignatureAlgorithm.SHA256, Severity.HIGH)
        val app = app("com.split", base = "/s/base.apk", splits = listOf("/s/split_payload.apk"))
        hasher.digests["/s/split_payload.apk" to HashAlgorithm.SHA256] = MALWARE_SHA256

        scanner(listOf(app)).scan().toList()

        val result = results.saved.getValue("com.split")
        assertEquals(Verdict.MALICIOUS, result.verdict)
        assertTrue(result.reasons.first().detail.contains("split_payload.apk"))
        assertEquals(listOf("/s/base.apk", "/s/split_payload.apk"), hasher.calls.map { it.first })
    }

    @Test
    fun `only algorithms present in the signature store are computed`() = runTest {
        val app = app("com.legacy", base = "/l/base.apk")
        scanner(listOf(app)).scan().toList()
        assertEquals(listOf(HashAlgorithm.SHA256), hasher.calls.map { it.second })

        signatures.add("d41d8cd98f00b204e9800998ecf8427e", SignatureAlgorithm.MD5, Severity.LOW)
        hasher.digests["/l/base.apk" to HashAlgorithm.MD5] = "d41d8cd98f00b204e9800998ecf8427e"
        hasher.calls.clear()
        scanner(listOf(app)).scan().toList()

        assertEquals(setOf(HashAlgorithm.SHA256, HashAlgorithm.MD5), hasher.calls.map { it.second }.toSet())
        assertEquals(Verdict.MALICIOUS, results.saved.getValue("com.legacy").verdict)
    }

    @Test
    fun `unreadable APK is reported, not fatal`() = runTest {
        hasher.failures["/locked/base.apk"] = HashResult.PermissionDenied

        scanner(listOf(app("com.locked", base = "/locked/base.apk"))).scan().toList()

        val result = results.saved.getValue("com.locked")
        assertNull(result.apkSha256)
        assertEquals(Verdict.CLEAN, result.verdict)
        assertTrue(
            result.reasons.any {
                it.code == ScanReason.Code.HASH_FAILED && "permission denied" in it.detail
            }
        )
    }

    @Test
    fun `allow-listed app skips heuristics but known malware is still flagged`() = runTest {
        signatures.add(MALWARE_SHA256, SignatureAlgorithm.SHA256, Severity.HIGH)
        allowList.allowed += setOf("com.trusted", "com.trusted.evil")
        hasher.digests["/te/base.apk" to HashAlgorithm.SHA256] = MALWARE_SHA256
        val risky = setOf("android.permission.READ_SMS", "android.permission.SYSTEM_ALERT_WINDOW")

        scanner(
            listOf(
                app("com.trusted", installer = null, base = "/t/base.apk", permissions = risky),
                app("com.trusted.evil", base = "/te/base.apk")
            )
        ).scan().toList()

        assertEquals(Verdict.CLEAN, results.saved.getValue("com.trusted").verdict)
        assertEquals(Verdict.MALICIOUS, results.saved.getValue("com.trusted.evil").verdict)
    }

    @Test
    fun `workers never exceed the parallelism bound`() = runTest {
        hasher.delayMillis = 100
        val apps = (1..20).map { app("com.app$it", base = "/a$it/base.apk") }
        val scanner = scanner(apps, parallelism = 3)

        scanner.scan().toList()

        assertEquals(3, hasher.maxConcurrent.get())
        assertEquals(20, results.saved.size)
        // 20 apps, 100 ms each, 3 at a time -> 7 rounds of virtual time.
        assertEquals(700L, testScheduler.currentTime)
    }

    @Test
    fun `pause stops new apps from starting until resumed`() = runTest {
        hasher.delayMillis = 100
        val control = ScanControl()
        val apps = (1..6).map { app("com.app$it", base = "/a$it/base.apk") }
        val events = mutableListOf<ScanProgress>()
        val job = launch { scanner(apps, parallelism = 2).scan(control).toList(events) }

        advanceTimeBy(150) // first two apps done, next two in flight
        control.pause()
        advanceTimeBy(1_000) // in-flight apps finish, nothing new starts
        val scannedWhilePaused = results.saved.size
        assertEquals(4, scannedWhilePaused)
        assertTrue(control.isPaused.value)

        control.resume()
        advanceUntilIdle()
        job.join()
        assertEquals(6, results.saved.size)
        assertTrue(events.last() is ScanProgress.Completed)
    }

    @Test
    fun `cancelling stops the scan, keeps saved results and does not prune`() = runTest {
        hasher.delayMillis = 100
        results.saved["com.uninstalled"] = results.placeholder("com.uninstalled")
        val apps = (1..10).map { app("com.app$it", base = "/a$it/base.apk") }
        val events = mutableListOf<ScanProgress>()
        val job = launch { scanner(apps, parallelism = 2).scan().toList(events) }

        advanceTimeBy(250)
        job.cancel()
        advanceUntilIdle()

        assertEquals(4, results.saved.keys.count { it.startsWith("com.app") })
        assertTrue("stale result kept: scan did not complete", results.saved.containsKey("com.uninstalled"))
        assertTrue(events.none { it is ScanProgress.Completed })
    }

    @Test
    fun `completed scan removes results of uninstalled apps`() = runTest {
        results.saved["com.uninstalled"] = results.placeholder("com.uninstalled")

        scanner(listOf(app("com.kept", base = "/k/base.apk"))).scan().toList()

        assertEquals(setOf("com.kept"), results.saved.keys)
    }

    @Test
    fun `scanPackage scans and saves one installed app`() = runTest {
        signatures.add(MALWARE_SHA256, SignatureAlgorithm.SHA256, Severity.CRITICAL)
        hasher.digests["/new/base.apk" to HashAlgorithm.SHA256] = MALWARE_SHA256
        val apps = listOf(app("com.new", base = "/new/base.apk"), app("com.other", base = "/other/base.apk"))

        val result = scanner(apps).scanPackage("com.new")

        assertEquals(Verdict.MALICIOUS, result?.verdict)
        assertEquals(setOf("com.new"), results.saved.keys)
        assertEquals(listOf("/new/base.apk"), hasher.calls.map { it.first }.distinct())
    }

    @Test
    fun `a critical YARA match makes an app from Play malicious and is explained`() = runTest {
        patterns.matchesByPath["/tool/base.apk"] =
            listOf(
                YaraMatch(
                    "BlackShield_Test_File",
                    meta = mapOf("severity" to "critical", "description" to "test file"),
                    location = "base.apk!classes.dex"
                )
            )
        val result = scanApps(this, listOf(app("com.tool", base = "/tool/base.apk"))).single()

        assertEquals(Verdict.MALICIOUS, result.verdict)
        val reason = result.reasons.single { it.ruleId == "yara_critical" }
        assertEquals(100, reason.points)
        assertEquals(
            listOf("YARA rule BlackShield_Test_File matched in base.apk!classes.dex: test file"),
            reason.evidence
        )
        assertEquals(listOf(listOf("/tool/base.apk")), patterns.calls)
    }

    @Test
    fun `YARA is skipped for trusted apps and known malware, and its problems are reported`() = runTest {
        signatures.add(MALWARE_SHA256, SignatureAlgorithm.SHA256, Severity.CRITICAL)
        hasher.digests["/evil/base.apk" to HashAlgorithm.SHA256] = MALWARE_SHA256
        allowList.allowed += "com.trusted"
        patterns.problems = listOf("YARA scan of base.apk stopped after 10000 ms")
        val results =
            scanApps(
                this,
                listOf(
                    app("com.evil", base = "/evil/base.apk"),
                    app("com.trusted", base = "/trusted/base.apk"),
                    app("com.plain", base = "/plain/base.apk", splits = listOf("/plain/split.apk"))
                )
            ).associateBy { it.packageName }

        assertEquals(listOf(listOf("/plain/base.apk", "/plain/split.apk")), patterns.calls)
        assertTrue(
            results.getValue("com.plain").reasons.any {
                it.code == ScanReason.Code.ANALYSIS_INCOMPLETE && it.detail.contains("stopped after")
            }
        )
    }

    @Test
    fun `scanPackage of an app that is gone returns null and saves nothing`() = runTest {
        assertNull(scanner(emptyList()).scanPackage("com.gone"))
        assertTrue(results.saved.isEmpty())
    }

    // --- helpers -------------------------------------------------------------------------

    private suspend fun scanApps(scope: TestScope, apps: List<InstalledApp>): List<ScanResult> =
        scope.scanner(apps).scan().toList().filterIsInstance<ScanProgress.AppScanned>().map { it.result }

    private class FakePatternScanner : ApkPatternScanner {
        val matchesByPath = mutableMapOf<String, List<YaraMatch>>()
        var problems: List<String> = emptyList()
        val calls = mutableListOf<List<String>>()

        override fun scan(apkPaths: List<String>): PatternScanResult = synchronized(this) {
            calls += apkPaths
            PatternScanResult(apkPaths.flatMap { matchesByPath[it].orEmpty() }, problems, rulesVersion = 1)
        }
    }

    private fun TestScope.scanner(apps: List<InstalledApp>, parallelism: Int = 4) = InstalledAppScanner(
        appSource = FakeAppSource(apps),
        hasher = hasher,
        signatures = signatures,
        results = results,
        allowList = allowList,
        analyzer = analyzer,
        assessor = RiskAssessor(RiskRulesSource { TestProfiles.SHIPPED_RULES }, clock),
        patterns = patterns,
        dispatcher = StandardTestDispatcher(testScheduler),
        parallelism = parallelism,
        clock = clock
    )

    private fun TestScope.advanceTimeBy(millis: Long) {
        testScheduler.advanceTimeBy(millis)
        runCurrent()
    }

    private fun app(
        packageName: String,
        base: String,
        splits: List<String> = emptyList(),
        installer: String? = "com.android.vending",
        permissions: Set<String> = emptySet()
    ) = InstalledApp(
        packageName = packageName,
        label = packageName.substringAfterLast('.'),
        versionCode = 1,
        apkPaths = listOf(base) + splits,
        isSystemApp = false,
        isDebuggable = false,
        installerPackage = installer,
        requestedPermissions = permissions
    )

    private class FakeAppSource(private val apps: List<InstalledApp>) : InstalledAppSource {
        override suspend fun installedApps() = apps

        override suspend fun installedApp(packageName: String) = apps.firstOrNull { it.packageName == packageName }
    }

    /** Profiles straight from [InstalledApp], plus per-package components set by a test. */
    private class FakeAnalyzer : ApkAnalyzer {
        val components = java.util.concurrent.ConcurrentHashMap<String, List<AppComponent>>()

        override fun analyzeArchive(path: String): AppProfile? = null

        override fun startSession() = ApkAnalyzer.Session { app ->
            TestProfiles.profile(
                packageName = app.packageName,
                installer = app.installerPackage,
                system = app.isSystemApp,
                debuggable = app.isDebuggable,
                permissions = app.requestedPermissions,
                components =
                    listOf(TestProfiles.activity("${app.packageName}.Main")) + components[app.packageName].orEmpty()
            )
        }
    }

    /** Returns configured digests (default: a digest derived from the path), tracks concurrency. */
    private class FakeHasher : FileHasher {
        val digests = HashMap<Pair<String, HashAlgorithm>, String>()
        val failures = HashMap<String, HashResult>()
        val calls = mutableListOf<Pair<String, HashAlgorithm>>()
        val maxConcurrent = AtomicInteger()
        private val running = AtomicInteger()
        var delayMillis = 0L

        override suspend fun hashFile(path: String, algorithm: HashAlgorithm): HashResult {
            synchronized(calls) { calls += path to algorithm }
            val now = running.incrementAndGet()
            maxConcurrent.accumulateAndGet(now, ::maxOf)
            try {
                if (delayMillis > 0) delay(delayMillis)
                failures[path]?.let { return it }
                val hex = digests[path to algorithm] ?: "%0${algorithm.digestLength * 2}x".format(path.hashCode())
                return HashResult.Success(algorithm, hex, bytesHashed = 1)
            } finally {
                running.decrementAndGet()
            }
        }
    }

    private class FakeSignatureRepository : SignatureRepository {
        private val rows = HashMap<String, MalwareSignature>()

        fun add(hash: String, algorithm: SignatureAlgorithm, severity: Severity) {
            rows[hash] = MalwareSignature(hash, algorithm, "Test.Family", "unit-test", severity, 0)
        }

        override suspend fun isKnownMalicious(hash: String) = hash.lowercase() in rows

        override suspend fun findMatches(hashes: Collection<String>) =
            hashes.mapNotNull { rows[it.lowercase()] }.associateBy { it.hash }

        override suspend fun algorithmsInUse() = rows.values.mapTo(HashSet()) { it.algorithm }

        override suspend fun insertAll(signatures: Sequence<MalwareSignature>, batchSize: Int): ImportResult {
            signatures.forEach { rows[it.hash] = it }
            return ImportResult(rows.size, 0)
        }

        override suspend fun count() = rows.size.toLong()
    }

    private class FakeScanResultRepository : ScanResultRepository {
        val saved = java.util.concurrent.ConcurrentHashMap<String, ScanResult>()
        private val flow = MutableStateFlow<Map<String, ScanResult>>(emptyMap())

        fun placeholder(packageName: String) =
            ScanResult(0, packageName, packageName, 1, null, Verdict.CLEAN, 0, emptyList(), 0)

        override fun observeLatest(): Flow<List<ScanResult>> = flow.map { it.values.toList() }

        override suspend fun save(result: ScanResult) {
            saved[result.packageName] = result
            flow.value = saved.toMap()
        }

        override suspend fun retainOnly(installed: Set<String>) {
            saved.keys.retainAll(installed)
        }

        override suspend fun find(packageName: String) = saved[packageName]
    }

    private class FakeAllowListRepository : AllowListRepository {
        val allowed = mutableSetOf<String>()

        override suspend fun allowedPackages() = allowed.toSet()

        override fun observeAllowedPackages(): Flow<Set<String>> = MutableStateFlow(allowed.toSet())

        override suspend fun allow(packageName: String) {
            allowed += packageName
        }

        override suspend fun remove(packageName: String) {
            allowed -= packageName
        }
    }

    private companion object {
        val MALWARE_SHA256 = "ee".repeat(32)
    }
}
