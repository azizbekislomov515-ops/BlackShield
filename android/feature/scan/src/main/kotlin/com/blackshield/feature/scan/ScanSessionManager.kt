package com.blackshield.feature.scan

import com.blackshield.core.data.model.ScanSource
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.scanner.FullScanSummary
import com.blackshield.core.scanner.ScanRecorder
import com.blackshield.core.scanner.apps.InstalledAppScanner
import com.blackshield.core.scanner.apps.ScanControl
import com.blackshield.core.scanner.apps.ScanProgress
import java.time.Clock
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

sealed interface ScanStatus {
    data object Idle : ScanStatus

    data class Running(
        val scanned: Int,
        val total: Int,
        val currentApp: String?,
        val paused: Boolean,
        val threats: Int = 0,
        val source: ScanSource = ScanSource.MANUAL
    ) : ScanStatus

    data class Finished(val total: Int, val malicious: Int, val suspicious: Int, val durationMillis: Long) : ScanStatus
}

/**
 * Runs full scans of installed apps for the whole app: "Scan now" on Home or Scan, and scheduled
 * scans. One scan at a time; it keeps running when the user leaves the screen. Every finished
 * scan is written to the history.
 */
@Singleton
class ScanSessionManager
@Inject
constructor(
    private val scanner: InstalledAppScanner,
    private val recorder: ScanRecorder,
    private val clock: Clock
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val mutableStatus = MutableStateFlow<ScanStatus>(ScanStatus.Idle)
    val status: StateFlow<ScanStatus> = mutableStatus.asStateFlow()

    private var job: Job? = null
    private var control: ScanControl? = null
    private var finished: CompletableDeferred<ScanStatus.Finished?>? = null

    /** Starts a scan; false if one is already running. */
    @Synchronized
    fun start(source: ScanSource = ScanSource.MANUAL): Boolean {
        if (job?.isActive == true) return false
        val scanControl = ScanControl().also { control = it }
        val done = CompletableDeferred<ScanStatus.Finished?>().also { finished = it }
        job =
            scope.launch {
                val flagged = mutableListOf<String>()
                var outcome: ScanStatus.Finished? = null
                try {
                    scanner.scan(scanControl).collect { progress ->
                        outcome = handle(progress, scanControl, source, flagged) ?: outcome
                    }
                } finally {
                    done.complete(outcome)
                }
                outcome?.let { result ->
                    recorder.recordFullScan(
                        FullScanSummary(
                            source = source,
                            finishedAt = clock.millis(),
                            scanned = result.total,
                            malicious = result.malicious,
                            suspicious = result.suspicious,
                            durationMillis = result.durationMillis,
                            flagged = flagged
                        )
                    )
                }
            }
        return true
    }

    /** For the scheduled worker: starts a scan (or joins the running one) and waits for it. */
    suspend fun runToCompletion(source: ScanSource): ScanStatus.Finished? {
        start(source)
        return finished?.await()
    }

    fun pause() {
        control?.pause()
        mutableStatus.update { (it as? ScanStatus.Running)?.copy(paused = true) ?: it }
    }

    fun resume() {
        control?.resume()
        mutableStatus.update { (it as? ScanStatus.Running)?.copy(paused = false) ?: it }
    }

    /** Stops the scan; results saved so far stay. Not recorded as a finished scan. */
    @Synchronized
    fun cancel() {
        job?.cancel()
        job = null
        control = null
        mutableStatus.value = ScanStatus.Idle
    }

    private fun handle(
        progress: ScanProgress,
        scanControl: ScanControl,
        source: ScanSource,
        flagged: MutableList<String>
    ): ScanStatus.Finished? {
        when (progress) {
            is ScanProgress.Started ->
                mutableStatus.value =
                    ScanStatus.Running(0, progress.total, null, scanControl.isPaused.value, source = source)

            is ScanProgress.AppScanned -> {
                if (progress.result.verdict != Verdict.CLEAN) flagged += progress.result.appLabel
                mutableStatus.value =
                    ScanStatus.Running(
                        progress.scanned,
                        progress.total,
                        progress.result.appLabel,
                        scanControl.isPaused.value,
                        threats = flagged.size,
                        source = source
                    )
            }

            is ScanProgress.Completed -> {
                val result = ScanStatus.Finished(
                    progress.total,
                    progress.malicious,
                    progress.suspicious,
                    progress.durationMillis
                )
                mutableStatus.value = result
                return result
            }
        }
        return null
    }
}
