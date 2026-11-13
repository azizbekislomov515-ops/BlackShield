package com.blackshield.core.sync

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject

/**
 * Runs one signature sync. Retryable failures return [Result.retry], so WorkManager reschedules
 * with exponential backoff (see [SignatureSyncScheduler]); after [MAX_ATTEMPTS] the attempt is
 * given up and the periodic schedule tries again next period. If WorkManager stops the worker
 * (constraints lost), the coroutine is cancelled and any open transaction rolls back.
 */
@HiltWorker
class SignatureSyncWorker
@AssistedInject
constructor(
    @Assisted appContext: Context,
    @Assisted params: WorkerParameters,
    private val engine: SignatureSyncEngine
) : CoroutineWorker(appContext, params) {
    override suspend fun doWork(): Result = when (val result = engine.sync()) {
        is SyncResult.Success -> Result.success()
        is SyncResult.Failure -> resultFor(result.error, runAttemptCount)
    }

    companion object {
        const val MAX_ATTEMPTS = 5

        /** [attempt] is WorkManager's zero-based `runAttemptCount`. */
        fun resultFor(error: SyncErrorKind, attempt: Int): Result =
            if (error.retryable && attempt + 1 < MAX_ATTEMPTS) Result.retry() else Result.failure()
    }
}
