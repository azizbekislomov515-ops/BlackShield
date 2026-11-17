package com.blackshield.feature.scan.schedule

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.hilt.work.HiltWorker
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.blackshield.core.data.AppEntry
import com.blackshield.core.data.model.ScanSource
import com.blackshield.core.data.prefs.AppSettingsRepository
import com.blackshield.core.data.prefs.ScanSchedule
import com.blackshield.feature.scan.R
import com.blackshield.feature.scan.ScanSessionManager
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.distinctUntilChanged

/** Runs the scheduled full scan and tells the user when it found something. */
@HiltWorker
class ScheduledScanWorker
@AssistedInject
constructor(
    @Assisted appContext: Context,
    @Assisted params: WorkerParameters,
    private val scans: ScanSessionManager
) : CoroutineWorker(appContext, params) {
    override suspend fun doWork(): Result {
        val result = scans.runToCompletion(ScanSource.SCHEDULED) ?: return Result.retry()
        val threats = result.malicious + result.suspicious
        if (threats > 0) notifyThreats(threats)
        return Result.success()
    }

    private fun notifyThreats(count: Int) {
        val context = applicationContext
        val allowed =
            Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
                ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) ==
                PackageManager.PERMISSION_GRANTED
        if (!allowed) return
        context.getSystemService(NotificationManager::class.java)?.createNotificationChannel(
            NotificationChannel(
                CHANNEL,
                context.getString(R.string.schedule_channel),
                NotificationManager.IMPORTANCE_DEFAULT
            )
        )
        val open =
            PendingIntent.getActivity(
                context,
                0,
                AppEntry.intent(context).putExtra(EXTRA_SHOW_THREATS, true),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
        val notification =
            NotificationCompat
                .Builder(context, CHANNEL)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentTitle(context.resources.getQuantityString(R.plurals.schedule_threats_title, count, count))
                .setContentText(context.getString(R.string.schedule_threats_body))
                .setContentIntent(open)
                .setAutoCancel(true)
                .build()
        @Suppress("MissingPermission") // checked above
        NotificationManagerCompat.from(context).notify(NOTIFICATION_ID, notification)
    }

    companion object {
        const val CHANNEL = "scheduled_scans"
        const val EXTRA_SHOW_THREATS = "com.blackshield.SHOW_THREATS"
        private const val NOTIFICATION_ID = 4001
    }
}

/** Keeps WorkManager's periodic scan in line with the user's schedule. */
@Singleton
class ScanScheduler
@Inject
constructor(
    private val workManager: WorkManager,
    private val settings: AppSettingsRepository
) {
    /** Call once per process from a long-lived scope; never returns. */
    suspend fun run() {
        settings.scanSchedule.distinctUntilChanged().collect(::apply)
    }

    fun apply(schedule: ScanSchedule) {
        val days = schedule.frequency.days
        if (days == null) {
            workManager.cancelUniqueWork(WORK_NAME)
            return
        }
        val request =
            PeriodicWorkRequestBuilder<ScheduledScanWorker>(days, TimeUnit.DAYS)
                .setConstraints(constraints(schedule))
                .addTag(WORK_NAME)
                .build()
        // UPDATE keeps the next run time when only the constraints change.
        workManager.enqueueUniquePeriodicWork(WORK_NAME, ExistingPeriodicWorkPolicy.UPDATE, request)
    }

    companion object {
        const val WORK_NAME = "scheduled-scan"

        fun constraints(schedule: ScanSchedule): Constraints = Constraints
            .Builder()
            .setRequiresBatteryNotLow(true)
            .setRequiresCharging(schedule.requiresCharging)
            .setRequiresDeviceIdle(schedule.requiresIdle)
            .build()
    }
}
