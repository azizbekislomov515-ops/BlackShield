package com.blackshield.core.sync

import com.blackshield.core.data.model.MalwareSignature
import com.blackshield.core.data.model.Severity
import com.blackshield.core.data.model.SignatureAlgorithm
import com.blackshield.core.data.repository.SignatureSyncStore
import com.blackshield.core.network.InvalidPayloadException

/**
 * Validates wire values and maps them to the local model. Strict on purpose: an unknown
 * algorithm or severity fails the whole sync instead of silently dropping rows, because a
 * dropped row would make the local count disagree with the server's and force a full snapshot
 * on every sync. Protocol changes come with a new API version.
 */
internal object SignatureMapper {
    const val UNKNOWN_FAMILY = "Unknown"
    private const val FAMILY_MAX_LENGTH = 128

    fun algorithm(value: String): SignatureAlgorithm = when (value) {
        "md5" -> SignatureAlgorithm.MD5
        "sha1" -> SignatureAlgorithm.SHA1
        "sha256" -> SignatureAlgorithm.SHA256
        else -> throw InvalidPayloadException("unknown algorithm")
    }

    fun severity(value: String): Severity = when (value) {
        "low" -> Severity.LOW
        "medium" -> Severity.MEDIUM
        "high" -> Severity.HIGH
        "critical" -> Severity.CRITICAL
        else -> throw InvalidPayloadException("unknown severity")
    }

    /** Lower-case hex of exactly the algorithm's length. */
    fun hash(value: String, algorithm: SignatureAlgorithm): String {
        if (value.length != algorithm.hexLength || !value.all { it in '0'..'9' || it in 'a'..'f' }) {
            throw InvalidPayloadException("invalid ${algorithm.name} hash")
        }
        return value
    }

    fun signature(hash: String, algorithm: String, family: String?, severity: String, addedAt: Long): MalwareSignature {
        val parsedAlgorithm = algorithm(algorithm)
        return MalwareSignature(
            hash = hash(hash, parsedAlgorithm),
            algorithm = parsedAlgorithm,
            family = family?.trim()?.take(FAMILY_MAX_LENGTH)?.ifEmpty { null } ?: UNKNOWN_FAMILY,
            source = SignatureSyncStore.SOURCE,
            severity = severity(severity),
            addedAt = addedAt
        )
    }
}
