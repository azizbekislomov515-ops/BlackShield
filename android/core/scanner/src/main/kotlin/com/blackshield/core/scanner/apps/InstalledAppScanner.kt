package com.blackshield.core.scanner.apps

import com.blackshield.core.data.model.ScanResult
import com.blackshield.core.data.model.SignatureAlgorithm
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.data.repository.AllowListRepository
import com.blackshield.core.data.repository.ScanResultRepository
import com.blackshield.core.data.repository.SignatureRepository
import com.blackshield.core.scanner.analysis.ApkAnalyzer
import com.blackshield.core.scanner.di.ScanDispatcher
import com.blackshield.core.scanner.di.ScanParallelism
import com.blackshield.core.scanner.hash.FileHasher
import com.blackshield.core.scanner.hash.HashAlgorithm
import com.blackshield.core.scanner.hash.HashResult
import java.time.Clock
import java.util.concurrent.atomic.AtomicInteger
import javax.inject.Inject
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface ScanProgress {
    data class Started(val total: Int) : ScanProgress

    data class AppScanned(val result: ScanResult, val scanned: Int, val total: Int) : ScanProgress

    data class Completed(val total: Int, val malicious: Int, val suspicious: Int, val durationMillis: Long) :
        ScanProgress
}

/** Pause/resume handle for a running scan. Cancel by cancelling the collecting coroutine. */
class ScanControl {
    private val paused = MutableStateFlow(false)

    val isPaused: StateFlow<Boolean> = paused.asStateFlow()

    /** Workers finish the app they are on, then wait. */
    fun pause() {
        paused.value = true
    }

    fun resume() {
        paused.value = false
    }

    internal suspend fun awaitResumed() {
        paused.first { !it }
    }
}

/**
 * Scans every installed app: hashes the base and split APKs with the native engine, looks the
 * digests up in the signature store, analyzes the APK statically ([ApkAnalyzer]), assesses risk
 * ([RiskAssessor]), persists each result and emits progress.
 *
 * Apps are processed by [parallelism] workers on a bounded dispatcher. Cancelling collection stops
 * the scan (in-flight native hashes are cancelled too); results saved so far are kept. When the scan
 * completes, results for apps that are no longer installed are removed.
 */
class InstalledAppScanner
@Inject
constructor(
    private val appSource: InstalledAppSource,
    private val hasher: FileHasher,
    private val signatures: SignatureRepository,
    private val results: ScanResultRepository,
    private val allowList: AllowListRepository,
    private val analyzer: ApkAnalyzer,
    private val assessor: RiskAssessor,
    @param:ScanDispatcher private val dispatcher: CoroutineDispatcher,
    @param:ScanParallelism private val parallelism: Int,
    private val clock: Clock
) {
    fun scan(control: ScanControl = ScanControl()): Flow<ScanProgress> = channelFlow {
        val startedAt = clock.millis()
        val apps = withContext(dispatcher) { appSource.installedApps() }
        // Only compute digests that can match something in the store; SHA-256 is always stored.
        val algorithms =
            signatures.algorithmsInUse().map { it.toHashAlgorithm() }.toSet() + HashAlgorithm.SHA256
        val allowed = allowList.allowedPackages()
        val analysis = analyzer.startSession()
        send(ScanProgress.Started(apps.size))

        val queue = Channel<InstalledApp>(Channel.UNLIMITED)
        apps.forEach { queue.trySend(it) }
        queue.close()

        val scanned = AtomicInteger()
        val malicious = AtomicInteger()
        val suspicious = AtomicInteger()
        coroutineScope {
            repeat(parallelism.coerceIn(1, maxOf(1, apps.size))) {
                launch(dispatcher) {
                    for (app in queue) {
                        control.awaitResumed()
                        val result = scanApp(app, algorithms, app.packageName in allowed, analysis)
                        results.save(result)
                        when (result.verdict) {
                            Verdict.MALICIOUS -> malicious.incrementAndGet()
                            Verdict.SUSPICIOUS -> suspicious.incrementAndGet()
                            Verdict.CLEAN -> Unit
                        }
                        send(ScanProgress.AppScanned(result, scanned.incrementAndGet(), apps.size))
                    }
                }
            }
        }

        results.retainOnly(apps.mapTo(HashSet()) { it.packageName })
        send(ScanProgress.Completed(apps.size, malicious.get(), suspicious.get(), clock.millis() - startedAt))
    }

    private suspend fun scanApp(
        app: InstalledApp,
        algorithms: Set<HashAlgorithm>,
        allowListed: Boolean,
        analysis: ApkAnalyzer.Session
    ): ScanResult {
        val digestsByPath = LinkedHashMap<String, MutableMap<HashAlgorithm, String>>()
        val failures = mutableListOf<String>()
        for (path in app.apkPaths) {
            for (algorithm in algorithms) {
                when (val hash = hasher.hashFile(path, algorithm)) {
                    is HashResult.Success -> digestsByPath.getOrPut(path) { mutableMapOf() }[algorithm] =
                        hash.hexDigest

                    else -> failures += "${path.substringAfterLast('/')} ($algorithm): ${hash.describe()}"
                }
            }
        }

        // One batched lookup per app (base + splits, every algorithm).
        val signatureByHash = signatures.findMatches(digestsByPath.values.flatMap { it.values })
        val matches =
            digestsByPath.flatMap { (path, digests) ->
                digests.values.mapNotNull { digest -> signatureByHash[digest]?.let { SignatureMatch(path, it) } }
            }
        val assessment = assessor.assess(analysis.analyze(app), matches, failures, allowListed)
        val baseApk = app.apkPaths.first()
        return ScanResult(
            packageName = app.packageName,
            appLabel = app.label,
            versionCode = app.versionCode,
            apkSha256 = digestsByPath[baseApk]?.get(HashAlgorithm.SHA256),
            verdict = assessment.verdict,
            riskScore = assessment.riskScore,
            reasons = assessment.reasons,
            scannedAt = clock.millis()
        )
    }

    private fun HashResult.describe(): String = when (this) {
        is HashResult.Success -> "ok"
        HashResult.FileNotFound -> "file not found"
        HashResult.PermissionDenied -> "permission denied"
        HashResult.Cancelled -> "cancelled"
        is HashResult.Error -> "${reason.name.lowercase()} (errno $errno)"
    }

    private fun SignatureAlgorithm.toHashAlgorithm(): HashAlgorithm = when (this) {
        SignatureAlgorithm.MD5 -> HashAlgorithm.MD5
        SignatureAlgorithm.SHA1 -> HashAlgorithm.SHA1
        SignatureAlgorithm.SHA256 -> HashAlgorithm.SHA256
    }
}
