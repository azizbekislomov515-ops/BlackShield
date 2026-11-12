package com.blackshield.core.network

import com.blackshield.core.network.model.HealthResponse
import retrofit2.http.GET

/** Retrofit interface for the BlackShield backend. */
interface BlackShieldApi {
    @GET("health")
    suspend fun health(): HealthResponse
}
