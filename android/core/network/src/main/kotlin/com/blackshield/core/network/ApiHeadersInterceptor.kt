package com.blackshield.core.network

import okhttp3.Interceptor
import okhttp3.Response

/**
 * Adds `User-Agent` to every request and the API key (`X-API-Key`) only to requests for the
 * configured backend origin, so the key never reaches another host. Redirects are disabled on the
 * client (see [BlackShieldHttp]), so a redirect cannot carry it elsewhere either.
 */
internal class ApiHeadersInterceptor(private val config: NetworkConfig) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val builder = request.newBuilder().header("User-Agent", config.userAgent)
        val url = request.url
        val sameOrigin =
            url.scheme == config.baseUrl.scheme && url.host == config.baseUrl.host && url.port == config.baseUrl.port
        if (sameOrigin && config.apiKey.isNotEmpty()) {
            builder.header(API_KEY_HEADER, config.apiKey)
        }
        return chain.proceed(builder.build())
    }

    companion object {
        const val API_KEY_HEADER = "X-API-Key"
    }
}
