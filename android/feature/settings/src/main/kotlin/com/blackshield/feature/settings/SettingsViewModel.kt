package com.blackshield.feature.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.blackshield.core.data.prefs.AppSettingsRepository
import com.blackshield.core.data.prefs.ScanSchedule
import com.blackshield.core.data.prefs.ThemeMode
import com.blackshield.core.data.prefs.UserPreferencesRepository
import com.blackshield.core.data.repository.SignatureSyncStore
import com.blackshield.core.sync.SignatureSyncScheduler
import com.blackshield.core.sync.SyncErrorKind
import com.blackshield.core.sync.SyncStateRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import java.time.Instant
import javax.inject.Inject
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/** Status of the local signature database, as shown in Settings. */
data class SignatureDatabaseStatus(
    /** 0 until the first sync has completed. */
    val version: Long = 0,
    /** Every signature in the store, synced or built in. */
    val count: Long = 0,
    val lastSuccessAt: Instant? = null,
    val syncing: Boolean = false,
    /** Why the latest attempt failed; null if it succeeded (or none ran yet). */
    val lastError: SyncErrorKind? = null
)

data class SettingsUiState(
    val realTimeProtectionEnabled: Boolean = true,
    val wifiOnly: Boolean = false,
    val signatures: SignatureDatabaseStatus = SignatureDatabaseStatus(),
    /** Real-time protection also checks new APK files in Downloads. */
    val watchDownloads: Boolean = false,
    /** SAF tree URIs of extra folders to watch. */
    val watchedFolders: List<String> = emptyList(),
    val schedule: ScanSchedule = ScanSchedule(),
    val theme: ThemeMode = ThemeMode.SYSTEM,
    val crashReports: Boolean = false
)

@HiltViewModel
class SettingsViewModel
@Inject
constructor(
    private val userPreferences: UserPreferencesRepository,
    private val appSettings: AppSettingsRepository,
    private val syncScheduler: SignatureSyncScheduler,
    syncState: SyncStateRepository,
    signatureStore: SignatureSyncStore
) : ViewModel() {
    val uiState: StateFlow<SettingsUiState> =
        combine(
            userPreferences.realTimeProtectionEnabled,
            userPreferences.signatureSyncWifiOnly,
            syncState.state,
            signatureStore.observeSignatureCount(),
            syncScheduler.isSyncing
        ) { realTime, wifiOnly, sync, count, syncing ->
            SettingsUiState(
                realTimeProtectionEnabled = realTime,
                wifiOnly = wifiOnly,
                signatures =
                    SignatureDatabaseStatus(
                        version = sync.version,
                        count = count,
                        lastSuccessAt = sync.lastSuccessAt,
                        syncing = syncing,
                        lastError = sync.lastError
                    )
            )
        }.combine(combine(userPreferences.watchDownloads, userPreferences.watchedFolders, ::Pair)) {
                settings,
                (downloads, folders)
            ->
            settings.copy(watchDownloads = downloads, watchedFolders = folders.sorted())
        }.combine(
            combine(appSettings.scanSchedule, appSettings.themeMode, appSettings.crashReportsEnabled, ::Triple)
        ) { settings, (schedule, theme, crashReports) ->
            settings.copy(schedule = schedule, theme = theme, crashReports = crashReports)
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MILLIS), SettingsUiState())

    fun setRealTimeProtectionEnabled(enabled: Boolean) {
        viewModelScope.launch { userPreferences.setRealTimeProtectionEnabled(enabled) }
    }

    fun setWatchDownloads(watch: Boolean) {
        viewModelScope.launch { userPreferences.setWatchDownloads(watch) }
    }

    fun addWatchedFolder(treeUri: String) {
        viewModelScope.launch { userPreferences.addWatchedFolder(treeUri) }
    }

    fun removeWatchedFolder(treeUri: String) {
        viewModelScope.launch { userPreferences.removeWatchedFolder(treeUri) }
    }

    fun setWifiOnly(wifiOnly: Boolean) {
        viewModelScope.launch { userPreferences.setSignatureSyncWifiOnly(wifiOnly) }
    }

    fun syncNow() = syncScheduler.syncNow()

    fun setSchedule(schedule: ScanSchedule) {
        viewModelScope.launch { appSettings.setScanSchedule(schedule) }
    }

    fun setTheme(theme: ThemeMode) {
        viewModelScope.launch { appSettings.setThemeMode(theme) }
    }

    fun setCrashReports(enabled: Boolean) {
        viewModelScope.launch { appSettings.setCrashReportsEnabled(enabled) }
    }

    private companion object {
        const val STOP_TIMEOUT_MILLIS = 5_000L
    }
}
