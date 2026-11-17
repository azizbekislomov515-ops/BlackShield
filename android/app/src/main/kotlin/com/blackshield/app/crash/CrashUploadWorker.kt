package com.blackshield.app.crash

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.blackshield.core.data.prefs.AppSettingsRepository
import com.blackshield.core.network.BlackShieldApi
import com.blackshield.core.network.model.CrashReportRequest
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import java.io.File
import java.io.IOException
import kotlinx.coroutines.flow.first
import retrofit2.HttpException
import timber.log.Timber

/** Sends pending crash reports, if the user still has crash reports on. */
@HiltWorker
class CrashUploadWorker
@AssistedInject
constructor(
    @Assisted context: Context,
    @Assisted params: WorkerParameters,
    private val api: BlackShieldApi,
    private val settings: AppSettingsRepository
) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result = when {
        !settings.crashReportsEnabled.first() -> {
            CrashReports.deleteAll(applicationContext)
            Result.success()
        }

        CrashReports.pending(applicationContext).all { send(it) } -> Result.success()

        else -> Result.retry()
    }

    /** False when the report must wait for a retry; otherwise it is sent or refused for good, and deleted. */
    private suspend fun send(file: File): Boolean {
        val report = CrashReports.read(file)
        val status = if (report == null) UNREADABLE else post(report)
        val retry = status == NETWORK_ERROR || status == TOO_MANY_REQUESTS || status in SERVER_ERRORS
        if (!retry) file.delete()
        return !retry
    }

    private suspend fun post(report: CrashReportRequest): Int = try {
        api.reportCrash(report).code()
    } catch (e: IOException) {
        Timber.d(e, "Crash report not sent; will retry")
        NETWORK_ERROR
    } catch (e: HttpException) {
        e.code()
    }

    companion object {
        private const val WORK_NAME = "crash-upload"
        private const val NETWORK_ERROR = -1
        private const val UNREADABLE = -2
        private const val TOO_MANY_REQUESTS = 429
        private val SERVER_ERRORS = 500..599

        fun enqueue(context: Context) {
            val request = OneTimeWorkRequestBuilder<CrashUploadWorker>()
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .build()
            WorkManager.getInstance(context).enqueueUniqueWork(WORK_NAME, ExistingWorkPolicy.KEEP, request)
        }
    }
}
