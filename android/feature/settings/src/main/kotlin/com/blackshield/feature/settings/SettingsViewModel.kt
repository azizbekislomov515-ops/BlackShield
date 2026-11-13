package com.blackshield.feature.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
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
    val signatures: SignatureDatabaseStatus = SignatureDatabaseStatus()
)

@HiltViewModel
class SettingsViewModel
@Inject
constructor(
    private val userPreferences: UserPreferencesRepository,
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
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MILLIS), SettingsUiState())

    fun setRealTimeProtectionEnabled(enabled: Boolean) {
        viewModelScope.launch { userPreferences.setRealTimeProtectionEnabled(enabled) }
    }

    fun setWifiOnly(wifiOnly: Boolean) {
        viewModelScope.launch { userPreferences.setSignatureSyncWifiOnly(wifiOnly) }
    }

    fun syncNow() = syncScheduler.syncNow()

    private companion object {
        const val STOP_TIMEOUT_MILLIS = 5_000L
    }
}
