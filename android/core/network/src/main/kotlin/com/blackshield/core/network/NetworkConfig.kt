package com.blackshield.core.network

import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl

/**
 * Connection settings for the BlackShield backend. Production values come from [BuildConfig]
 * (see core/network/build.gradle.kts); tests build their own.
 *
 * [readTimeout] bounds the gap between two reads, not the whole call, so a large snapshot can
 * stream for as long as data keeps arriving. There is deliberately no call timeout.
 */
data class NetworkConfig(
    val baseUrl: HttpUrl,
    val apiKey: String,
    val certificatePins: List<CertificatePin> = emptyList(),
    val userAgent: String = "BlackShield-Android",
    val connectTimeout: Duration = 15.seconds,
    val readTimeout: Duration = 30.seconds,
    val writeTimeout: Duration = 15.seconds,
    val httpLogging: Boolean = false
) {
    init {
        require(baseUrl.encodedPath.endsWith("/")) { "baseUrl must end with '/'" }
    }

    override fun toString(): String =
        "NetworkConfig(baseUrl=$baseUrl, apiKey=${if (apiKey.isEmpty()) "<none>" else "<set>"}, " +
            "certificatePins=$certificatePins)"

    companion object {
        fun fromBuildConfig(): NetworkConfig = NetworkConfig(
            baseUrl = BuildConfig.API_BASE_URL.toHttpUrl(),
            apiKey = BuildConfig.API_KEY,
            certificatePins = CertificatePin.parseList(BuildConfig.CERTIFICATE_PINS),
            httpLogging = BuildConfig.DEBUG
        )
    }
}

/**
 * One OkHttp certificate pin: the base64 SHA-256 of a certificate's SubjectPublicKeyInfo for
 * [hostPattern] (an exact host or `*.example.com` / `**.example.com`).
 */
data class CertificatePin(val hostPattern: String, val pin: String) {
    init {
        require(HOST.matches(hostPattern)) { "invalid certificate pin host: $hostPattern" }
        require(PIN.matches(pin)) { "certificate pin must look like sha256/<44 base64 chars>" }
    }

    companion object {
        private val HOST = Regex("""^(\*\*?\.)?[A-Za-z0-9.-]+$""")
        private val PIN = Regex("""^sha256/[A-Za-z0-9+/]{43}=$""")

        /** Parses `host=sha256/...,host=sha256/...`; blank means no pinning. */
        fun parseList(config: String): List<CertificatePin> = config
            .split(',')
            .map(String::trim)
            .filter(String::isNotEmpty)
            .map { entry ->
                val (host, pin) =
                    entry.split('=', limit = 2).takeIf { it.size == 2 }
                        ?: throw IllegalArgumentException("certificate pin entries must be host=sha256/...")
                CertificatePin(host.trim(), pin.trim())
            }
    }
}
