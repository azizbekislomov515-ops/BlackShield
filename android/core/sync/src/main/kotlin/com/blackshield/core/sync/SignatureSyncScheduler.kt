package com.blackshield.core.sync

import android.os.Build
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkInfo
import androidx.work.WorkManager
import com.blackshield.core.data.prefs.UserPreferencesRepository
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

/**
 * Schedules [SignatureSyncWorker]:
 *
 * - **Periodic**, every [PERIODIC_INTERVAL_HOURS] hours, on an unmetered network when the user's
 *   Wi-Fi-only setting is on, else any network.
 * - **Initial**, once, expedited, when the app starts and has never synced. Follows the setting.
 * - **Manual** ("Sync now"), expedited, on any network: the user asked for it.
 *
 * The engine serializes concurrent runs, so overlapping requests are harmless.
 */
@Singleton
class SignatureSyncScheduler
@Inject
constructor(
    private val workManager: WorkManager,
    private val preferences: UserPreferencesRepository,
    private val syncState: SyncStateRepository
) {
    /** True while any sync request is running. */
    val isSyncing: Flow<Boolean> =
        combine(UNIQUE_NAMES.map { name -> workManager.getWorkInfosForUniqueWorkFlow(name) }) { infos ->
            infos.any { list -> list.any { it.state == WorkInfo.State.RUNNING } }
        }.distinctUntilChanged()

    /**
     * Call once per process start, from a long-lived scope: enqueues the initial sync if needed,
     * then keeps the periodic request's network constraint in line with the setting. Never returns.
     */
    suspend fun run() {
        val state = syncState.current()
        if (state.version == 0L && state.lastSuccessAt == null) {
            enqueueOnce(INITIAL_WORK, networkFor(preferences.signatureSyncWifiOnly.first()))
        }
        preferences.signatureSyncWifiOnly.distinctUntilChanged().collect(::schedulePeriodic)
    }

    fun syncNow() = enqueueOnce(MANUAL_WORK, NetworkType.CONNECTED)

    private fun schedulePeriodic(wifiOnly: Boolean) {
        val request =
            PeriodicWorkRequestBuilder<SignatureSyncWorker>(PERIODIC_INTERVAL_HOURS, TimeUnit.HOURS)
                .setConstraints(
                    Constraints
                        .Builder()
                        .setRequiredNetworkType(networkFor(wifiOnly))
                        .setRequiresBatteryNotLow(true)
                        .setRequiresStorageNotLow(true)
                        .build()
                ).setBackoffCriteria(BackoffPolicy.EXPONENTIAL, BACKOFF_SECONDS, TimeUnit.SECONDS)
                .addTag(TAG)
                .build()
        // UPDATE keeps the current period (and a running sync) and only swaps the constraints.
        workManager.enqueueUniquePeriodicWork(PERIODIC_WORK, ExistingPeriodicWorkPolicy.UPDATE, request)
    }

    private fun enqueueOnce(name: String, network: NetworkType) {
        val request =
            OneTimeWorkRequestBuilder<SignatureSyncWorker>()
                .setConstraints(Constraints.Builder().setRequiredNetworkType(network).build())
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, BACKOFF_SECONDS, TimeUnit.SECONDS)
                .addTag(TAG)
                .apply {
                    // Before Android 12, expedited work runs as a foreground service and needs a
                    // notification (getForegroundInfo); there it runs as regular work instead.
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
                    }
                }.build()
        // KEEP: a request already queued or running is not restarted.
        workManager.enqueueUniqueWork(name, ExistingWorkPolicy.KEEP, request)
    }

    private fun networkFor(wifiOnly: Boolean) = if (wifiOnly) NetworkType.UNMETERED else NetworkType.CONNECTED

    companion object {
        const val TAG = "signature-sync"
        const val PERIODIC_WORK = "signature-sync-periodic"
        const val INITIAL_WORK = "signature-sync-initial"
        const val MANUAL_WORK = "signature-sync-manual"
        private val UNIQUE_NAMES = listOf(PERIODIC_WORK, INITIAL_WORK, MANUAL_WORK)
        const val PERIODIC_INTERVAL_HOURS = 6L
        const val BACKOFF_SECONDS = 30L
    }
}
