package com.blackshield.core.sync

import android.database.SQLException
import com.blackshield.core.data.repository.StoreVerificationException
import com.blackshield.core.network.InvalidPayloadException
import java.io.EOFException
import java.io.IOException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException
import kotlinx.serialization.SerializationException
import retrofit2.HttpException

/** The snapshot stream failed while downloading (connection dropped, stalled, short body). */
internal class IncompleteDownloadException(cause: IOException) : IOException("download interrupted", cause)

/** Writing the downloaded snapshot to disk failed. */
internal class SyncStorageException(cause: IOException) : IOException("could not save the download", cause)

internal object SyncErrors {
    fun classify(error: Throwable): SyncErrorKind {
        // OkHttp may report another route's connection error and attach the pin failure as a
        // suppressed exception, so look through causes and suppressed exceptions.
        if (error.related().any { it is SSLPeerUnverifiedException || it is SSLHandshakeException }) {
            return SyncErrorKind.CERTIFICATE
        }
        return when (error) {
            is HttpException -> when (error.code()) {
                HTTP_UNAUTHORIZED, HTTP_FORBIDDEN -> SyncErrorKind.UNAUTHORIZED
                HTTP_TOO_MANY_REQUESTS -> SyncErrorKind.RATE_LIMITED
                else -> SyncErrorKind.SERVER
            }

            is InvalidPayloadException, is SerializationException, is StoreVerificationException ->
                SyncErrorKind.CORRUPT_DATA

            is SyncStorageException, is SQLException -> SyncErrorKind.STORAGE

            is IncompleteDownloadException, is EOFException -> SyncErrorKind.INCOMPLETE_DOWNLOAD

            is IOException -> SyncErrorKind.NETWORK

            else -> SyncErrorKind.UNKNOWN
        }
    }

    private fun Throwable.related(): Sequence<Throwable> = sequence {
        val seen = HashSet<Throwable>()
        val pending = ArrayDeque(listOf(this@related))
        while (pending.isNotEmpty()) {
            val next = pending.removeFirst()
            if (!seen.add(next)) continue
            yield(next)
            next.cause?.let(pending::addLast)
            next.suppressed.forEach(pending::addLast)
        }
    }

    private const val HTTP_UNAUTHORIZED = 401
    private const val HTTP_FORBIDDEN = 403
    private const val HTTP_TOO_MANY_REQUESTS = 429
}
