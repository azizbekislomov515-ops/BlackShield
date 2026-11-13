package com.blackshield.core.network

import kotlin.time.toJavaDuration
import kotlinx.serialization.json.Json
import okhttp3.CertificatePinner
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.kotlinx.serialization.asConverterFactory

/** Builds the HTTP stack. Production goes through DI; tests call these directly. */
object BlackShieldHttp {
    val json: Json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
    }

    /**
     * - Responses are gzip-decoded transparently: OkHttp sends `Accept-Encoding: gzip` itself,
     *   except where a call sets the header explicitly to receive the raw stream (snapshot).
     * - Redirects are not followed: the API never redirects, and following one could send the
     *   API key or pinned traffic somewhere unexpected.
     * - Logging (debug builds only) is BASIC: request line and status, never headers or bodies.
     */
    fun createClient(config: NetworkConfig): OkHttpClient = OkHttpClient
        .Builder()
        .connectTimeout(config.connectTimeout.toJavaDuration())
        .readTimeout(config.readTimeout.toJavaDuration())
        .writeTimeout(config.writeTimeout.toJavaDuration())
        .followRedirects(false)
        .followSslRedirects(false)
        .apply {
            if (config.certificatePins.isNotEmpty()) {
                val pinner = CertificatePinner.Builder()
                config.certificatePins.forEach { pinner.add(it.hostPattern, it.pin) }
                certificatePinner(pinner.build())
            }
        }.addInterceptor(ApiHeadersInterceptor(config))
        .apply {
            if (config.httpLogging) {
                addInterceptor(HttpLoggingInterceptor().setLevel(HttpLoggingInterceptor.Level.BASIC))
            }
        }.build()

    fun createApi(config: NetworkConfig, client: OkHttpClient = createClient(config)): BlackShieldApi = Retrofit
        .Builder()
        .baseUrl(config.baseUrl)
        .client(client)
        .addConverterFactory(json.asConverterFactory("application/json".toMediaType()))
        .build()
        .create(BlackShieldApi::class.java)
}
