package com.blackshield.core.sync

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject

/**
 * Runs one signature sync, then one YARA rules sync ([YaraRulesSyncEngine]) and one Web Shield
 * domain-list sync ([DomainSyncEngine]). They are independent: a failure of one never keeps the
 * others from being applied.
 *
 * Retryable failures return [Result.retry], so WorkManager reschedules with exponential backoff
 * (see [SignatureSyncScheduler]); after [MAX_ATTEMPTS] the attempt is given up and the periodic
 * schedule tries again next period. If WorkManager stops the worker (constraints lost), the
 * coroutine is cancelled and any open transaction rolls back.
 */
@HiltWorker
class SignatureSyncWorker
@AssistedInject
constructor(
    @Assisted appContext: Context,
    @Assisted params: WorkerParameters,
    private val engine: SignatureSyncEngine,
    private val rules: YaraRulesSyncEngine,
    private val domains: DomainSyncEngine
) : CoroutineWorker(appContext, params) {
    override suspend fun doWork(): Result {
        val signatureError = (engine.sync() as? SyncResult.Failure)?.error
        val rulesError = (rules.sync() as? RulesSyncResult.Failure)?.error
        val domainsError = (domains.sync() as? DomainSyncResult.Failure)?.error
        return resultFor(listOfNotNull(signatureError, rulesError, domainsError), runAttemptCount)
    }

    companion object {
        const val MAX_ATTEMPTS = 5

        /** [attempt] is WorkManager's zero-based `runAttemptCount`. */
        fun resultFor(error: SyncErrorKind, attempt: Int): Result = resultFor(listOf(error), attempt)

        /** Success only when nothing failed; retried while any failure is retryable. */
        fun resultFor(errors: List<SyncErrorKind>, attempt: Int): Result = when {
            errors.isEmpty() -> Result.success()
            errors.any { it.retryable } && attempt + 1 < MAX_ATTEMPTS -> Result.retry()
            else -> Result.failure()
        }
    }
}
