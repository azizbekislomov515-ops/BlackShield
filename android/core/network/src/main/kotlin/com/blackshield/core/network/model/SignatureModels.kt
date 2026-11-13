package com.blackshield.core.network.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** `GET /v1/signatures/version`. [count] is the number of active signatures in [version]. */
@Serializable
data class SignatureVersionResponse(
    val version: Long,
    @SerialName("created_at") val createdAt: String? = null,
    val count: Long
)

/** One page of `GET /v1/signatures/delta`. Every hash appears at most once across all pages. */
@Serializable
data class SignatureDeltaResponse(
    val since: Long,
    val until: Long,
    @SerialName("latest_version") val latestVersion: Long,
    val additions: List<DeltaAddition>,
    val removals: List<DeltaRemoval>,
    @SerialName("next_cursor") val nextCursor: String? = null
)

/** Upsert this signature. Algorithm and severity are lower case (`sha256`, `high`). */
@Serializable
data class DeltaAddition(
    val hash: String,
    val algorithm: String,
    val family: String? = null,
    val severity: String,
    val version: Long
)

/** Delete this signature if present. */
@Serializable
data class DeltaRemoval(val hash: String, val algorithm: String, val version: Long)

@Serializable
data class ReputationLookupRequest(val hashes: List<String>) {
    init {
        require(hashes.size in 1..MAX_HASHES) { "between 1 and $MAX_HASHES hashes per lookup" }
    }

    companion object {
        const val MAX_HASHES = 100
    }
}

@Serializable
data class ReputationLookupResponse(val version: Long, val results: List<ReputationVerdict>)

/** `verdict` is `malicious` or `unknown`; `unknown` means "not a known signature", not "safe". */
@Serializable
data class ReputationVerdict(
    val hash: String,
    val verdict: String,
    val family: String? = null,
    val severity: String? = null
)
