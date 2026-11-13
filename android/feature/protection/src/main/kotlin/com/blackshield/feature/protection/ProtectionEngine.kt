package com.blackshield.feature.protection

import android.content.Context
import android.os.SystemClock
import com.blackshield.core.scanner.apps.InstalledAppScanner
import com.blackshield.core.scanner.files.ApkCandidate
import com.blackshield.core.scanner.files.ApkFileScanner
import com.blackshield.feature.protection.logic.AlertPolicy
import com.blackshield.feature.protection.logic.KeyedDebouncer
import com.blackshield.feature.protection.logic.ThreatAlert
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import timber.log.Timber

/**
 * Turns install and file events into scans and warnings. Owned by [RealtimeProtectionService],
 * which [attach]es it to its lifetime; all work runs in that scope, so stopping the service stops
 * pending scans.
 */
class ProtectionEngine
@Inject
constructor(
    @param:ApplicationContext private val context: Context,
    private val appScanner: InstalledAppScanner,
    private val fileScanner: ApkFileScanner,
    private val notifications: ProtectionNotifications,
    private val state: ProtectionStateStore
) {
    private lateinit var scope: CoroutineScope
    private lateinit var packages: KeyedDebouncer<String, Long>
    private lateinit var files: KeyedDebouncer<String, ApkCandidate>

    /** Versions of files already scanned, so repeated observer callbacks do not rescan them. */
    private val scannedFiles = object : LinkedHashMap<String, Unit>(SEEN_CAPACITY, LOAD_FACTOR, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Unit>?) = size > SEEN_CAPACITY
    }

    fun attach(scope: CoroutineScope) {
        this.scope = scope
        packages = KeyedDebouncer(scope, PACKAGE_QUIET_MILLIS) { pkg, receivedAt -> scanPackage(pkg, receivedAt) }
        files = KeyedDebouncer(scope, FILE_QUIET_MILLIS) { _, candidate -> scanFile(candidate) }
    }

    fun onPackageChanged(packageName: String) {
        if (packageName == context.packageName) return
        val receivedAt = SystemClock.elapsedRealtime()
        scope.launch { packages.submit(packageName, receivedAt) }
    }

    fun onPackageRemoved(packageName: String) {
        notifications.cancelThreat(packageKey(packageName))
    }

    fun onApkFile(candidate: ApkCandidate) {
        scope.launch { files.submit(candidate.path ?: candidate.uri.orEmpty(), candidate) }
    }

    private suspend fun scanPackage(packageName: String, receivedAt: Long) = guarded("package $packageName") {
        val result = appScanner.scanPackage(packageName) ?: return@guarded
        val elapsed = SystemClock.elapsedRealtime() - receivedAt
        Timber.i("Real-time scan of %s: %s (%d) in %d ms", packageName, result.verdict, result.riskScore, elapsed)
        if (AlertPolicy.shouldAlert(result.verdict, result.apkSha256, state.ignoredApks.first())) {
            notifications.showThreat(
                ThreatAlert(
                    key = packageKey(packageName),
                    verdict = result.verdict,
                    appName = result.appLabel,
                    packageName = packageName,
                    fileName = null,
                    sha256 = result.apkSha256,
                    riskScore = result.riskScore,
                    topReasons = ThreatAlert.topReasons(result.reasons)
                )
            )
        }
    }

    private suspend fun scanFile(candidate: ApkCandidate) = guarded("file ${candidate.displayName}") {
        val first = synchronized(scannedFiles) { scannedFiles.put(candidate.key, Unit) == null }
        if (!first) return@guarded
        val result = fileScanner.scan(candidate)
        Timber.i("Real-time scan of file %s: %s (%d)", candidate.displayName, result.verdict, result.riskScore)
        if (AlertPolicy.shouldAlert(result.verdict, result.sha256, state.ignoredApks.first())) {
            notifications.showThreat(
                ThreatAlert(
                    key = "file:${candidate.path ?: candidate.uri}",
                    verdict = result.verdict,
                    appName = result.appLabel ?: candidate.displayName,
                    packageName = result.packageName,
                    fileName = candidate.displayName,
                    sha256 = result.sha256,
                    riskScore = result.riskScore,
                    topReasons = ThreatAlert.topReasons(result.reasons)
                ),
                encodedFileResult = FileResultCodec.encode(result)
            )
        }
    }

    /** One bad app or file must not stop protection. */
    private suspend fun guarded(what: String, block: suspend () -> Unit) {
        try {
            block()
        } catch (e: CancellationException) {
            throw e
        } catch (
            @Suppress("TooGenericExceptionCaught") e: Exception
        ) {
            Timber.e(e, "Real-time scan of %s failed", what)
        }
    }

    companion object {
        /** ADDED and REPLACED arrive together on an update; 300 ms merges them and keeps alerts well under 3 s. */
        const val PACKAGE_QUIET_MILLIS = 300L

        /** A download touches its file many times; scan once it has been quiet for 1.5 s. */
        const val FILE_QUIET_MILLIS = 1_500L
        private const val SEEN_CAPACITY = 512
        private const val LOAD_FACTOR = 0.75f

        fun packageKey(packageName: String) = "pkg:$packageName"
    }
}
