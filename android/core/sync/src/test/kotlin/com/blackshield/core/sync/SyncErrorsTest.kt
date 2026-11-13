package com.blackshield.core.sync

import androidx.work.ListenableWorker.Result
import java.io.IOException
import java.net.ConnectException
import javax.net.ssl.SSLPeerUnverifiedException
import org.junit.Assert.assertEquals
import org.junit.Test

class SyncErrorsTest {
    @Test
    fun `pin failure hidden behind another route's error is a certificate error`() {
        val reported = ConnectException("Failed to connect to /[::1]:443")
        reported.addSuppressed(SSLPeerUnverifiedException("Certificate pinning failure!"))

        assertEquals(SyncErrorKind.CERTIFICATE, SyncErrors.classify(reported))
        assertEquals(SyncErrorKind.CERTIFICATE, SyncErrors.classify(IOException(SSLPeerUnverifiedException("pin"))))
        assertEquals(SyncErrorKind.NETWORK, SyncErrors.classify(ConnectException("refused")))
    }

    @Test
    fun `retryable errors retry until the attempt limit, permanent ones fail at once`() {
        assertEquals(Result.retry(), SignatureSyncWorker.resultFor(SyncErrorKind.NETWORK, attempt = 0))
        assertEquals(
            Result.retry(),
            SignatureSyncWorker.resultFor(SyncErrorKind.SERVER, attempt = SignatureSyncWorker.MAX_ATTEMPTS - 2)
        )
        assertEquals(
            Result.failure(),
            SignatureSyncWorker.resultFor(SyncErrorKind.SERVER, attempt = SignatureSyncWorker.MAX_ATTEMPTS - 1)
        )
        assertEquals(Result.failure(), SignatureSyncWorker.resultFor(SyncErrorKind.UNAUTHORIZED, attempt = 0))
        assertEquals(Result.failure(), SignatureSyncWorker.resultFor(SyncErrorKind.CERTIFICATE, attempt = 0))
    }
}
