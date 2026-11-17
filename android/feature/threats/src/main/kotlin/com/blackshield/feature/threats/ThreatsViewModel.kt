package com.blackshield.feature.threats

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.blackshield.core.data.model.FileThreat
import com.blackshield.core.data.model.ScanResult
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.data.quarantine.QuarantineOutcome
import com.blackshield.core.data.quarantine.QuarantineVault
import com.blackshield.core.data.repository.AllowListRepository
import com.blackshield.core.data.repository.ScanResultRepository
import com.blackshield.core.scanner.ScanRecorder
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.IOException
import java.time.Clock
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class ThreatsUiState(
    /** Harmful installed apps the user has not trusted, malicious first. */
    val apps: List<ScanResult> = emptyList(),
    val files: List<FileThreat> = emptyList(),
    val vault: List<FileThreat> = emptyList(),
    val selectedApp: ScanResult? = null
) {
    val openThreats: Int get() = apps.size + files.size
}

/** One-off results shown as a snackbar. */
enum class ThreatMessage {
    QUARANTINED,
    ORIGINAL_KEPT,
    QUARANTINE_FAILED,
    RESTORED,
    RESTORE_FAILED,
    DELETED,
    UNINSTALLED,
    TRUSTED
}

@HiltViewModel
class ThreatsViewModel
@Inject
constructor(
    @param:ApplicationContext private val context: Context,
    private val scanResults: ScanResultRepository,
    private val allowList: AllowListRepository,
    private val vault: QuarantineVault,
    private val recorder: ScanRecorder,
    private val clock: Clock
) : ViewModel() {
    private val selected = MutableStateFlow<String?>(null)
    private val messages = Channel<ThreatMessage>(Channel.BUFFERED)
    val events: Flow<ThreatMessage> = messages.receiveAsFlow()

    val state: StateFlow<ThreatsUiState> =
        combine(
            scanResults.observeLatest(),
            allowList.observeAllowedPackages(),
            vault.detected(),
            vault.quarantined(),
            selected
        ) {
                results,
                trusted,
                files,
                quarantined,
                selectedPackage
            ->
            val apps =
                results
                    .filter { it.verdict != Verdict.CLEAN && it.packageName !in trusted }
                    .sortedWith(
                        compareBy<ScanResult> {
                            it.verdict != Verdict.MALICIOUS
                        }.thenByDescending { it.riskScore }
                    )
            ThreatsUiState(apps, files, quarantined, apps.firstOrNull { it.packageName == selectedPackage })
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MILLIS), ThreatsUiState())

    fun showApp(packageName: String?) {
        selected.value = packageName
    }

    fun trust(packageName: String) {
        viewModelScope.launch {
            allowList.allow(packageName)
            selected.value = null
            messages.send(ThreatMessage.TRUSTED)
        }
    }

    /** Called when the system uninstall dialog returns: records the uninstall if the app is gone. */
    fun onUninstallFinished(packageName: String) {
        viewModelScope.launch {
            if (isInstalled(packageName)) return@launch
            scanResults.find(packageName)?.let { recorder.recordUninstall(it, clock.millis()) }
            scanResults.delete(packageName)
            selected.value = null
            messages.send(ThreatMessage.UNINSTALLED)
        }
    }

    fun quarantine(id: Long) {
        viewModelScope.launch {
            val message =
                when (vault.quarantine(id)) {
                    QuarantineOutcome.Quarantined -> ThreatMessage.QUARANTINED
                    QuarantineOutcome.OriginalKept -> ThreatMessage.ORIGINAL_KEPT
                    QuarantineOutcome.Failed -> ThreatMessage.QUARANTINE_FAILED
                }
            messages.send(message)
        }
    }

    fun ignore(id: Long) {
        viewModelScope.launch { vault.dismiss(id) }
    }

    /** Decrypts a quarantined file to [destination], a document the user created with the file picker. */
    fun restore(id: Long, destination: Uri) {
        viewModelScope.launch {
            val restored =
                withContext(Dispatchers.IO) {
                    try {
                        context.contentResolver.openOutputStream(destination)?.use { vault.restore(id, it) } ?: false
                    } catch (_: IOException) {
                        false
                    } catch (_: SecurityException) {
                        false
                    }
                }
            messages.send(if (restored) ThreatMessage.RESTORED else ThreatMessage.RESTORE_FAILED)
        }
    }

    fun deleteForever(id: Long) {
        viewModelScope.launch {
            vault.delete(id)
            messages.send(ThreatMessage.DELETED)
        }
    }

    private suspend fun isInstalled(packageName: String): Boolean = withContext(Dispatchers.IO) {
        try {
            context.packageManager.getPackageInfo(packageName, 0)
            true
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }
    }

    private companion object {
        const val STOP_TIMEOUT_MILLIS = 5_000L
    }
}
