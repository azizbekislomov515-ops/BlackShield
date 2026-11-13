package com.blackshield.core.sync

import com.blackshield.core.network.BlackShieldApi
import com.blackshield.core.network.InvalidPayloadException
import com.blackshield.core.scanner.yara.RulesInstallResult
import com.blackshield.core.scanner.yara.YaraRulesInstaller
import java.io.ByteArrayOutputStream
import java.io.InputStream
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.ResponseBody
import retrofit2.HttpException
import timber.log.Timber

sealed interface RulesSyncOutcome {
    /** The server has nothing newer than [version] (304, or an older/equal ruleset). */
    data class UpToDate(val version: Long) : RulesSyncOutcome

    /** A new ruleset was verified, compiled and is now in use. */
    data class Updated(val fromVersion: Long, val toVersion: Long) : RulesSyncOutcome

    /** The server has not published any ruleset yet (404). */
    data object NonePublished : RulesSyncOutcome

    /**
     * The download was refused (bad signature, digest mismatch, does not compile). The rules in
     * use are unchanged. Not retried: the same bytes would be refused again.
     */
    data class Refused(val reason: String) : RulesSyncOutcome
}

sealed interface RulesSyncResult {
    data class Success(val outcome: RulesSyncOutcome) : RulesSyncResult

    data class Failure(val error: SyncErrorKind, val cause: Throwable) : RulesSyncResult
}

/**
 * Fetches the latest signed YARA ruleset (`GET /v1/rules`) and hands it to the scanner, which
 * verifies the signature before anything is stored or used ([YaraRulesInstaller]). The version in
 * use goes out as `If-None-Match`, so an unchanged ruleset costs one 304.
 */
@Singleton
class YaraRulesSyncEngine
@Inject
constructor(
    private val api: BlackShieldApi,
    private val installer: YaraRulesInstaller
) {
    private val mutex = Mutex()

    suspend fun sync(): RulesSyncResult = mutex.withLock {
        val result =
            try {
                RulesSyncResult.Success(withContext(Dispatchers.IO) { runSync() })
            } catch (e: CancellationException) {
                throw e
            } catch (
                @Suppress("TooGenericExceptionCaught") e: Exception
            ) {
                RulesSyncResult.Failure(SyncErrors.classify(e), e)
            }
        when (result) {
            is RulesSyncResult.Success -> Timber.i("YARA rules sync: %s", result.outcome)
            is RulesSyncResult.Failure -> Timber.w(result.cause, "YARA rules sync failed: %s", result.error)
        }
        result
    }

    private suspend fun runSync(): RulesSyncOutcome {
        val active = installer.activeVersion()
        val response = api.yaraRules(etag(active))
        return when {
            response.code() == HTTP_NOT_MODIFIED -> RulesSyncOutcome.UpToDate(active)
            response.code() == HTTP_NOT_FOUND -> RulesSyncOutcome.NonePublished
            !response.isSuccessful -> throw HttpException(response)
            else -> install(active, response.body() ?: throw InvalidPayloadException("empty rules response"))
        }
    }

    private fun install(active: Long, body: ResponseBody): RulesSyncOutcome {
        val json = body.use { readBounded(it.byteStream()) }.toString(Charsets.UTF_8)
        return when (val result = installer.install(json)) {
            is RulesInstallResult.Installed -> RulesSyncOutcome.Updated(active, result.version)

            is RulesInstallResult.NotNewer -> RulesSyncOutcome.UpToDate(result.activeVersion)

            is RulesInstallResult.Rejected -> RulesSyncOutcome.Refused(result.reason).also {
                Timber.w("Refused YARA rules from the server: %s", result.reason)
            }
        }
    }

    /** Rulesets are at most 1 MiB of text; anything much larger is not a ruleset. */
    private fun readBounded(input: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val chunk = ByteArray(CHUNK)
        while (true) {
            val read = input.read(chunk)
            if (read < 0) break
            out.write(chunk, 0, read)
            if (out.size() >
                MAX_BODY_BYTES
            ) {
                throw InvalidPayloadException("rules response larger than $MAX_BODY_BYTES bytes")
            }
        }
        return out.toByteArray()
    }

    companion object {
        /** JSON escaping can roughly double the 1 MiB rule text. */
        const val MAX_BODY_BYTES = 4 * 1024 * 1024
        private const val CHUNK = 16 * 1024
        private const val HTTP_NOT_MODIFIED = 304
        private const val HTTP_NOT_FOUND = 404

        fun etag(version: Long): String = "\"rules-$version\""
    }
}
