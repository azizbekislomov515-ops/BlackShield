package com.blackshield.feature.protection

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.blackshield.core.data.prefs.UserPreferencesRepository
import com.blackshield.core.scanner.ScannerEngine
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import kotlinx.coroutines.flow.first
import timber.log.Timber

/** Periodic background protection pass. Placeholder: verifies the native engine is reachable. */
@HiltWorker
class ProtectionWorker
@AssistedInject
constructor(
    @Assisted appContext: Context,
    @Assisted params: WorkerParameters,
    private val scannerEngine: ScannerEngine,
    private val userPreferences: UserPreferencesRepository
) : CoroutineWorker(appContext, params) {
    override suspend fun doWork(): Result {
        if (!userPreferences.realTimeProtectionEnabled.first()) {
            Timber.d("Real-time protection disabled; skipping protection pass")
            return Result.success()
        }
        Timber.d("Protection pass: %s", scannerEngine.ping())
        return Result.success()
    }
}
