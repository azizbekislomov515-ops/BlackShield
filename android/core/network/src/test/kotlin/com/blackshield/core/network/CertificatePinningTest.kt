package com.blackshield.core.network

import java.net.InetAddress
import javax.net.ssl.SSLPeerUnverifiedException
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

class CertificatePinningTest {
    private val server = MockWebServer()
    private lateinit var serverCertificate: HeldCertificate

    @Before
    fun setUp() {
        // One address only: with localhost resolving to both ::1 and 127.0.0.1, OkHttp would retry
        // the second route after the pin failure and report that connection error instead.
        server.start(InetAddress.getByName("127.0.0.1"), 0)
        serverCertificate =
            HeldCertificate.Builder().addSubjectAlternativeName(server.hostName).build()
        server.useHttps(
            HandshakeCertificates.Builder().heldCertificate(serverCertificate).build().sslSocketFactory()
        )
    }

    @After
    fun tearDown() {
        server.close()
    }

    @Test
    fun `connects when the server key matches a pin`() {
        server.enqueue(MockResponse.Builder().body("ok").build())
        val client = clientPinning(CertificatePinner.pin(serverCertificate.certificate))

        client.newCall(request()).execute().use { assertEquals(200, it.code) }
    }

    @Test
    fun `refuses a trusted certificate that matches no pin`() {
        server.enqueue(MockResponse.Builder().body("ok").build())
        val otherKey = HeldCertificate.Builder().build()
        val client = clientPinning(CertificatePinner.pin(otherKey.certificate))

        assertThrows(SSLPeerUnverifiedException::class.java) { client.newCall(request()).execute() }
    }

    @Test
    fun `parses pin configuration and rejects malformed entries`() {
        val pin = "sha256/" + "A".repeat(43) + "="

        assertEquals(
            listOf(CertificatePin("api.example.com", pin), CertificatePin("*.example.com", pin)),
            CertificatePin.parseList(" api.example.com=$pin , *.example.com=$pin ")
        )
        assertEquals(emptyList<CertificatePin>(), CertificatePin.parseList(""))
        assertThrows(IllegalArgumentException::class.java) { CertificatePin.parseList("api.example.com") }
        assertThrows(IllegalArgumentException::class.java) { CertificatePin.parseList("api.example.com=sha1/abc") }
        assertThrows(IllegalArgumentException::class.java) { CertificatePin.parseList("bad host=$pin") }
    }

    /** The production client (pins from [NetworkConfig]) trusting the test CA. */
    private fun clientPinning(pin: String): OkHttpClient {
        val config =
            NetworkConfig(
                baseUrl = server.url("/"),
                apiKey = "key",
                certificatePins = listOf(CertificatePin(server.hostName, pin))
            )
        val trust = HandshakeCertificates.Builder().addTrustedCertificate(serverCertificate.certificate).build()
        return BlackShieldHttp
            .createClient(config)
            .newBuilder()
            .sslSocketFactory(trust.sslSocketFactory(), trust.trustManager)
            .build()
    }

    private fun request() = Request.Builder().url(server.url("/health")).build()
}
