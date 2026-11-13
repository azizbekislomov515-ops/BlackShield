package com.blackshield.core.network

import com.blackshield.core.network.model.DomainDeltaResponse
import com.blackshield.core.network.model.DomainVersionResponse
import com.blackshield.core.network.model.HealthResponse
import com.blackshield.core.network.model.ReputationLookupRequest
import com.blackshield.core.network.model.ReputationLookupResponse
import com.blackshield.core.network.model.SignatureDeltaResponse
import com.blackshield.core.network.model.SignatureVersionResponse
import okhttp3.ResponseBody
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Query
import retrofit2.http.Streaming

/**
 * Retrofit interface for the BlackShield backend (docs/sync-protocol.md). JSON calls throw
 * [retrofit2.HttpException] for non-2xx responses and [java.io.IOException] for transport errors.
 */
interface BlackShieldApi {
    @GET("health")
    suspend fun health(): HealthResponse

    @GET("v1/signatures/version")
    suspend fun signatureVersion(): SignatureVersionResponse

    /** One page of the net changes since [since]; pass `nextCursor` back as [cursor]. */
    @GET("v1/signatures/delta")
    suspend fun signatureDelta(
        @Query("since") since: Long,
        @Query("limit") limit: Int,
        @Query("cursor") cursor: String? = null
    ): SignatureDeltaResponse

    /**
     * The full snapshot as NDJSON (read it with [SnapshotReader]). `Accept-Encoding` is set
     * explicitly, so OkHttp hands over the gzip stream as received (check `Content-Encoding`)
     * instead of decoding it: the caller stores the compressed bytes. Not buffered in memory.
     */
    @Streaming
    @Headers("Accept-Encoding: gzip")
    @GET("v1/signatures/full")
    suspend fun signatureSnapshot(): Response<ResponseBody>

    /**
     * The latest signed YARA ruleset as raw JSON (the caller verifies its signature before use).
     * 304 when [ifNoneMatch] (`"rules-<version>"`) names it, 404 when nothing is published yet.
     */
    @GET("v1/rules")
    suspend fun yaraRules(@Header("If-None-Match") ifNoneMatch: String?): Response<ResponseBody>

    @GET("v1/domains/version")
    suspend fun domainVersion(): DomainVersionResponse

    /** One page of the domain-list changes since [since] (0: the whole list). */
    @GET("v1/domains/delta")
    suspend fun domainDelta(
        @Query("since") since: Long,
        @Query("limit") limit: Int,
        @Query("cursor") cursor: String? = null
    ): DomainDeltaResponse

    /** Verdicts for up to 100 SHA-256 digests. Hashes only: never send file contents. */
    @POST("v1/reputation/lookup")
    suspend fun reputationLookup(@Body request: ReputationLookupRequest): ReputationLookupResponse
}
