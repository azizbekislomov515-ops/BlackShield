package com.blackshield.feature.scan

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.blackshield.core.data.model.ScanResult
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.data.repository.AllowListRepository
import com.blackshield.core.data.repository.ScanResultRepository
import com.blackshield.core.scanner.apps.InstalledAppScanner
import com.blackshield.core.scanner.apps.ScanControl
import com.blackshield.core.scanner.apps.ScanProgress
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

sealed interface ScanStatus {
    data object Idle : ScanStatus

    data class Running(val scanned: Int, val total: Int, val currentApp: String?, val paused: Boolean) : ScanStatus

    data class Finished(val total: Int, val malicious: Int, val suspicious: Int, val durationMillis: Long) :
        ScanStatus
}

data class ScanUiState(
    /** Persisted results, most severe first. */
    val results: List<ScanResult> = emptyList(),
    val trustedPackages: Set<String> = emptySet(),
    val status: ScanStatus = ScanStatus.Idle,
    val selected: ScanResult? = null
)

@HiltViewModel
class ScanViewModel
@Inject
constructor(
    private val scanner: InstalledAppScanner,
    scanResults: ScanResultRepository,
    private val allowList: AllowListRepository
) : ViewModel() {
    private val status = MutableStateFlow<ScanStatus>(ScanStatus.Idle)
    private val selectedPackage = MutableStateFlow<String?>(null)
    private var scanJob: Job? = null
    private var control: ScanControl? = null

    // During a scan the database changes once per app (hundreds of times). Sorting runs off the
    // main thread, and list/progress updates are throttled so the UI recomposes a few times
    // per second instead of on every insert.
    val uiState: StateFlow<ScanUiState> =
        combine(
            scanResults
                .observeLatest()
                .map { it.sortedWith(SEVERITY_ORDER) }
                .throttleLatest(RESULTS_THROTTLE_MILLIS),
            allowList.observeAllowedPackages(),
            status.throttleLatest(STATUS_THROTTLE_MILLIS),
            selectedPackage
        ) { results, trusted, status, selected ->
            ScanUiState(
                results = results,
                trustedPackages = trusted,
                status = status,
                selected = results.firstOrNull { it.packageName == selected }
            )
        }.flowOn(Dispatchers.Default)
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MILLIS), ScanUiState())

    fun startScan() {
        if (scanJob?.isActive == true) return
        val scanControl = ScanControl().also { control = it }
        scanJob =
            viewModelScope.launch {
                scanner.scan(scanControl).collect { progress ->
                    status.value =
                        when (progress) {
                            is ScanProgress.Started ->
                                ScanStatus.Running(0, progress.total, null, scanControl.isPaused.value)

                            is ScanProgress.AppScanned ->
                                ScanStatus.Running(
                                    progress.scanned,
                                    progress.total,
                                    progress.result.appLabel,
                                    scanControl.isPaused.value
                                )

                            is ScanProgress.Completed ->
                                ScanStatus.Finished(
                                    progress.total,
                                    progress.malicious,
                                    progress.suspicious,
                                    progress.durationMillis
                                )
                        }
                }
            }
    }

    fun pause() {
        control?.pause()
        status.update { (it as? ScanStatus.Running)?.copy(paused = true) ?: it }
    }

    fun resume() {
        control?.resume()
        status.update { (it as? ScanStatus.Running)?.copy(paused = false) ?: it }
    }

    /** Stops the scan; results saved so far stay. */
    fun cancel() {
        scanJob?.cancel()
        scanJob = null
        control = null
        status.value = ScanStatus.Idle
    }

    fun showDetails(packageName: String) {
        selectedPackage.value = packageName
    }

    fun dismissDetails() {
        selectedPackage.value = null
    }

    /** Takes effect on the next scan. */
    fun setTrusted(packageName: String, trusted: Boolean) {
        viewModelScope.launch {
            if (trusted) allowList.allow(packageName) else allowList.remove(packageName)
        }
    }

    private companion object {
        const val STOP_TIMEOUT_MILLIS = 5_000L
        const val RESULTS_THROTTLE_MILLIS = 300L
        const val STATUS_THROTTLE_MILLIS = 100L

        val SEVERITY_ORDER: Comparator<ScanResult> =
            compareBy<ScanResult> {
                when (it.verdict) {
                    Verdict.MALICIOUS -> 0
                    Verdict.SUSPICIOUS -> 1
                    Verdict.CLEAN -> 2
                }
            }.thenBy(String.CASE_INSENSITIVE_ORDER) { it.appLabel }
    }
}
