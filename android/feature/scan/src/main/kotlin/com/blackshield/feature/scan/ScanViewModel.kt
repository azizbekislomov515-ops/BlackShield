package com.blackshield.feature.scan

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.blackshield.core.data.model.ScanResult
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.data.quarantine.QuarantineOutcome
import com.blackshield.core.data.quarantine.QuarantineVault
import com.blackshield.core.data.repository.AllowListRepository
import com.blackshield.core.data.repository.ScanResultRepository
import com.blackshield.core.scanner.ScanRecorder
import com.blackshield.core.scanner.files.ApkCandidate
import com.blackshield.core.scanner.files.ApkFileScanner
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** The outcome of scanning one APK file the user picked. */
data class FileScanUi(
    val name: String,
    val verdict: Verdict? = null,
    val riskScore: Int = 0,
    val topReason: String = "",
    /** Set for a harmful file: its entry in the Threats list. */
    val threatId: Long? = null,
    val quarantine: QuarantineOutcome? = null,
    val unreadable: Boolean = false
) {
    val scanning: Boolean get() = verdict == null && !unreadable
}

data class ScanUiState(
    /** Persisted results, most severe first. */
    val results: List<ScanResult> = emptyList(),
    val trustedPackages: Set<String> = emptySet(),
    val status: ScanStatus = ScanStatus.Idle,
    val selected: ScanResult? = null,
    val fileScan: FileScanUi? = null
)

@HiltViewModel
class ScanViewModel
@Inject
constructor(
    @param:ApplicationContext private val context: Context,
    private val scans: ScanSessionManager,
    scanResults: ScanResultRepository,
    private val allowList: AllowListRepository,
    private val fileScanner: ApkFileScanner,
    private val recorder: ScanRecorder,
    private val vault: QuarantineVault
) : ViewModel() {
    private val selectedPackage = MutableStateFlow<String?>(null)
    private val fileScan = MutableStateFlow<FileScanUi?>(null)

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
            scans.status.throttleLatest(STATUS_THROTTLE_MILLIS),
            selectedPackage,
            fileScan
        ) { results, trusted, status, selected, file ->
            ScanUiState(
                results = results,
                trustedPackages = trusted,
                status = status,
                selected = results.firstOrNull { it.packageName == selected },
                fileScan = file
            )
        }.flowOn(Dispatchers.Default)
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MILLIS), ScanUiState())

    fun startScan() {
        scans.start()
    }

    fun pause() = scans.pause()

    fun resume() = scans.resume()

    /** Stops the scan; results saved so far stay. */
    fun cancel() = scans.cancel()

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

    /** Scans an APK file picked with the system file picker. */
    fun scanFile(uri: Uri) {
        viewModelScope.launch {
            // Keep access for a later quarantine from the Threats screen, where the provider allows it.
            runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                )
            }
            val candidate = withContext(Dispatchers.IO) { candidateFor(context, uri) }
            if (candidate == null) {
                fileScan.value = FileScanUi(name = uri.lastPathSegment.orEmpty(), unreadable = true)
                return@launch
            }
            fileScan.value = FileScanUi(name = candidate.displayName)
            val result = fileScanner.scan(candidate)
            val threatId = recorder.recordFile(result)
            fileScan.value =
                FileScanUi(
                    name = candidate.displayName,
                    verdict = result.verdict,
                    riskScore = result.riskScore,
                    topReason = result.reasons.filter { it.points > 0 }.maxByOrNull { it.points }?.detail.orEmpty(),
                    threatId = threatId
                )
        }
    }

    fun quarantineScannedFile() {
        val id = fileScan.value?.threatId ?: return
        viewModelScope.launch {
            val outcome = vault.quarantine(id)
            fileScan.update { it?.copy(quarantine = outcome) }
        }
    }

    fun dismissFileScan() {
        fileScan.value = null
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

/** Name and size of a file picked with the system picker; null if the provider does not answer. */
internal fun candidateFor(context: Context, uri: Uri): ApkCandidate? = runCatching {
    context.contentResolver.query(
        uri,
        arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE),
        null,
        null,
        null
    )?.use { cursor ->
        if (!cursor.moveToFirst()) return@use null
        ApkCandidate(
            displayName = cursor.getString(0) ?: uri.lastPathSegment.orEmpty(),
            uri = uri.toString(),
            size = if (cursor.isNull(1)) 0 else cursor.getLong(1),
            lastModified = System.currentTimeMillis()
        )
    }
}.getOrNull()
