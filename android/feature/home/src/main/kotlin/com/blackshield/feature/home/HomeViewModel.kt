package com.blackshield.feature.home

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.blackshield.core.data.model.HistoryEvent
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.data.prefs.AppSettingsRepository
import com.blackshield.core.data.prefs.ScanFrequency
import com.blackshield.core.data.prefs.UserPreferencesRepository
import com.blackshield.core.data.quarantine.QuarantineVault
import com.blackshield.core.data.repository.AllowListRepository
import com.blackshield.core.data.repository.HistoryRepository
import com.blackshield.core.data.repository.ScanResultRepository
import com.blackshield.core.data.repository.SignatureSyncStore
import com.blackshield.core.sync.SignatureSyncScheduler
import com.blackshield.core.sync.SyncStateRepository
import com.blackshield.feature.protection.ProtectionController
import com.blackshield.feature.scan.ScanSessionManager
import com.blackshield.feature.scan.ScanStatus
import com.blackshield.feature.webshield.WebShieldRuntime
import com.blackshield.feature.webshield.WebShieldStatus
import dagger.hilt.android.lifecycle.HiltViewModel
import java.time.Clock
import javax.inject.Inject
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

data class HomeUiState(
    val score: SecurityScore =
        SecurityScoring.compute(ScoreInputs(false, false, null, null, 0, 0, false), 0),
    val scan: ScanStatus = ScanStatus.Idle,
    val lastScanAt: Long? = null,
    val definitionsVersion: Long = 0,
    val definitionsUpdatedAt: Long? = null,
    val signatureCount: Long = 0,
    val definitionsUpdating: Boolean = false,
    val realTimeEnabled: Boolean = false,
    val webShield: WebShieldStatus = WebShieldStatus.Off,
    val scanFrequency: ScanFrequency = ScanFrequency.OFF,
    val openThreats: Int = 0,
    val recent: List<HistoryEvent> = emptyList(),
    val now: Long = 0
)

/** Everything the dashboard shows, from the services that own it. */
@HiltViewModel
class HomeViewModel
@Inject
constructor(
    private val scans: ScanSessionManager,
    private val protection: ProtectionController,
    preferences: UserPreferencesRepository,
    settings: AppSettingsRepository,
    webShield: WebShieldRuntime,
    syncState: SyncStateRepository,
    private val syncScheduler: SignatureSyncScheduler,
    signatures: SignatureSyncStore,
    scanResults: ScanResultRepository,
    allowList: AllowListRepository,
    vault: QuarantineVault,
    history: HistoryRepository,
    private val clock: Clock
) : ViewModel() {
    private data class Threats(val malicious: Int, val suspicious: Int)

    private data class Definitions(val version: Long, val updatedAt: Long?, val count: Long, val updating: Boolean)

    private data class Protection(val realTime: Boolean, val webShield: WebShieldStatus, val frequency: ScanFrequency)

    private val threats: Flow<Threats> =
        combine(scanResults.observeLatest(), allowList.observeAllowedPackages(), vault.detected()) {
                results,
                trusted,
                files
            ->
            val apps = results.filter { it.packageName !in trusted }
            Threats(
                malicious =
                    apps.count { it.verdict == Verdict.MALICIOUS } + files.count { it.verdict == Verdict.MALICIOUS },
                suspicious =
                    apps.count { it.verdict == Verdict.SUSPICIOUS } + files.count { it.verdict == Verdict.SUSPICIOUS }
            )
        }

    private val definitions: Flow<Definitions> =
        combine(syncState.state, signatures.observeSignatureCount(), syncScheduler.isSyncing) { sync, count, syncing ->
            Definitions(sync.version, sync.lastSuccessAt?.toEpochMilli(), count, syncing)
        }

    private val protectionState: Flow<Protection> =
        combine(preferences.realTimeProtectionEnabled, webShield.status, settings.scanSchedule) {
                realTime,
                web,
                schedule
            ->
            Protection(realTime, web, schedule.frequency)
        }

    val state: StateFlow<HomeUiState> =
        combine(
            combine(scans.status, history.lastFullScan(), ::Pair),
            definitions,
            protectionState,
            threats,
            history.recent(RECENT_EVENTS)
        ) { (scan, lastScan), defs, prot, found, recent ->
            val now = clock.millis()
            val score =
                SecurityScoring.compute(
                    ScoreInputs(
                        realTimeProtection = prot.realTime,
                        webShield = prot.webShield is WebShieldStatus.On,
                        definitionsUpdatedAt = defs.updatedAt,
                        lastFullScanAt = lastScan?.occurredAt,
                        maliciousItems = found.malicious,
                        suspiciousItems = found.suspicious,
                        scheduledScans = prot.frequency != ScanFrequency.OFF
                    ),
                    now
                )
            HomeUiState(
                score = score,
                scan = scan,
                lastScanAt = lastScan?.occurredAt,
                definitionsVersion = defs.version,
                definitionsUpdatedAt = defs.updatedAt,
                signatureCount = defs.count,
                definitionsUpdating = defs.updating,
                realTimeEnabled = prot.realTime,
                webShield = prot.webShield,
                scanFrequency = prot.frequency,
                openThreats = found.malicious + found.suspicious,
                recent = recent,
                now = now
            )
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MILLIS), HomeUiState())

    fun scanNow() {
        scans.start()
    }

    fun setRealTimeProtection(enabled: Boolean) {
        viewModelScope.launch { protection.setEnabled(enabled) }
    }

    fun updateDefinitions() = syncScheduler.syncNow()

    private companion object {
        const val STOP_TIMEOUT_MILLIS = 5_000L
        const val RECENT_EVENTS = 3
    }
}
