package com.blackshield.feature.protection

import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit
import javax.inject.Inject

/** Schedules [ProtectionWorker]. Not started anywhere yet. */
class ProtectionScheduler
@Inject
constructor(private val workManager: WorkManager) {
    fun schedulePeriodicProtection() {
        val request =
            PeriodicWorkRequestBuilder<ProtectionWorker>(REPEAT_INTERVAL_HOURS, TimeUnit.HOURS)
                .setConstraints(Constraints.Builder().setRequiresBatteryNotLow(true).build())
                .build()
        workManager.enqueueUniquePeriodicWork(UNIQUE_WORK_NAME, ExistingPeriodicWorkPolicy.KEEP, request)
    }

    private companion object {
        const val UNIQUE_WORK_NAME = "blackshield-protection"
        const val REPEAT_INTERVAL_HOURS = 6L
    }
}
