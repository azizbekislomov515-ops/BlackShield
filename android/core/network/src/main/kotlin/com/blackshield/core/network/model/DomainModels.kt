package com.blackshield.core.network.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** `GET /v1/domains/version`. [count] is the number of active domains in [version]. */
@Serializable
data class DomainVersionResponse(
    val version: Long,
    @SerialName("created_at") val createdAt: String? = null,
    val count: Long
)

/** One page of `GET /v1/domains/delta`. Every domain appears at most once across all pages. */
@Serializable
data class DomainDeltaResponse(
    val since: Long,
    val until: Long,
    @SerialName("latest_version") val latestVersion: Long,
    val additions: List<DomainAddition>,
    val removals: List<DomainRemoval>,
    @SerialName("next_cursor") val nextCursor: String? = null
)

/** Block this domain and its subdomains. [category] is `malware` or `phishing`. */
@Serializable
data class DomainAddition(val domain: String, val category: String, val version: Long)

@Serializable
data class DomainRemoval(val domain: String, val version: Long)
