package com.blackshield.core.scanner.hash

/** Outcome of hashing one file or descriptor. */
sealed interface HashResult {
    data class Success(
        val algorithm: HashAlgorithm,
        /** Lower-case hexadecimal digest. */
        val hexDigest: String,
        val bytesHashed: Long
    ) : HashResult

    data object FileNotFound : HashResult

    data object PermissionDenied : HashResult

    /** Stopped through the caller's [android.os.CancellationSignal]. */
    data object Cancelled : HashResult

    data class Error(
        val reason: Reason,
        /** errno of the failing system call, 0 if not applicable. */
        val errno: Int
    ) : HashResult {
        enum class Reason { IO_ERROR, INVALID_ARGUMENT, INTERNAL_ERROR }
    }
}
