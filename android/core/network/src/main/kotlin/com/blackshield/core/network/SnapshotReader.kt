package com.blackshield.core.network

import java.io.EOFException
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import okio.BufferedSource

/** The payload is well-formed transport-wise but violates the protocol (corrupt data). */
class InvalidPayloadException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** The snapshot ended before its `end` line: a partial download. Retry. */
class TruncatedSnapshotException(message: String, cause: Throwable? = null) : EOFException(message) {
    init {
        cause?.let(::initCause)
    }
}

data class SnapshotHeader(val version: Long, val count: Long)

/** One snapshot row as sent: lower-case enum names, nullable family. Not validated beyond presence. */
data class SnapshotSignature(val hash: String, val algorithm: String, val family: String?, val severity: String)

/**
 * Pull parser for `GET /v1/signatures/full` NDJSON (docs/sync-protocol.md): a header line, one
 * line per signature, and an `end` line whose count must equal the number of signature lines.
 *
 * Reads one line at a time from an already-decoded [source], so memory use does not depend on
 * the snapshot size. Call [readHeader] once, then [next] until it returns null; null is only
 * returned after the end line has been verified, so a caller that reaches it has the complete
 * snapshot.
 */
class SnapshotReader(private val source: BufferedSource, private val json: Json = BlackShieldHttp.json) {
    private var header: SnapshotHeader? = null
    private var signatures = 0L
    private var finished = false

    fun readHeader(): SnapshotHeader {
        check(header == null) { "header already read" }
        val line = readLine() ?: throw TruncatedSnapshotException("empty snapshot")
        if (line.type != "header") invalid("snapshot does not start with a header")
        if (line.format != SUPPORTED_FORMAT) invalid("unsupported snapshot format ${line.format}")
        val version = line.version?.takeIf { it >= 0 } ?: invalid("header has no version")
        val count = line.count?.takeIf { it >= 0 } ?: invalid("header has no count")
        return SnapshotHeader(version, count).also { header = it }
    }

    /** The next signature, or null once the end line has been read and verified. */
    fun next(): SnapshotSignature? {
        val header = checkNotNull(header) { "call readHeader() first" }
        if (finished) return null
        val line = readLine() ?: throw TruncatedSnapshotException("snapshot ended after $signatures signatures")
        return when (line.type) {
            null -> {
                signatures++
                SnapshotSignature(
                    hash = line.hash ?: invalid("signature line has no hash"),
                    algorithm = line.algorithm ?: invalid("signature line has no algorithm"),
                    family = line.family,
                    severity = line.severity ?: invalid("signature line has no severity")
                )
            }

            "end" -> {
                if (line.version != header.version || line.count != signatures || signatures != header.count) {
                    invalid(
                        "end line (version ${line.version}, count ${line.count}) does not match the header " +
                            "(version ${header.version}, count ${header.count}) and $signatures lines received"
                    )
                }
                if (!source.exhausted()) invalid("data after the end line")
                finished = true
                null
            }

            else -> invalid("unexpected line type")
        }
    }

    private fun readLine(): SnapshotLine? {
        if (source.exhausted()) return null
        // Throws EOFException when there is no newline within the limit (or at all): truncated.
        val text = source.readUtf8LineStrict(MAX_LINE_BYTES)
        return try {
            json.decodeFromString(SnapshotLine.serializer(), text)
        } catch (e: SerializationException) {
            throw InvalidPayloadException("malformed snapshot line", e)
        } catch (e: IllegalArgumentException) {
            throw InvalidPayloadException("malformed snapshot line", e)
        }
    }

    private fun invalid(message: String): Nothing = throw InvalidPayloadException(message)

    @Serializable
    private data class SnapshotLine(
        val type: String? = null,
        val format: Int? = null,
        val version: Long? = null,
        val count: Long? = null,
        val hash: String? = null,
        val algorithm: String? = null,
        val family: String? = null,
        val severity: String? = null,
        @SerialName("created_at") val createdAt: String? = null
    )

    companion object {
        const val SUPPORTED_FORMAT = 1

        /** A signature line is ~150 bytes (64 hex digits + family of at most 128 chars). */
        const val MAX_LINE_BYTES = 4_096L
    }
}
