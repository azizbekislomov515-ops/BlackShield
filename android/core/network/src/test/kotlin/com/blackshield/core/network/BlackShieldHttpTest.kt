package com.blackshield.core.network

import com.blackshield.core.network.model.ReputationLookupRequest
import kotlinx.coroutines.test.runTest
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.Request
import okio.Buffer
import okio.GzipSink
import okio.buffer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import retrofit2.HttpException

class BlackShieldHttpTest {
    private val server = MockWebServer()
    private lateinit var config: NetworkConfig
    private lateinit var api: BlackShieldApi

    @Before
    fun setUp() {
        server.start()
        config = NetworkConfig(baseUrl = server.url("/"), apiKey = API_KEY, userAgent = "BlackShield-Test/1")
        api = BlackShieldHttp.createApi(config)
    }

    @After
    fun tearDown() {
        server.close()
    }

    @Test
    fun `sends the API key and user agent to the backend`() = runTest {
        server.enqueue(json("""{"version":7,"created_at":"2026-11-13T09:00:00+00:00","count":3}"""))

        val version = api.signatureVersion()

        assertEquals(7L, version.version)
        assertEquals(3L, version.count)
        val request = server.takeRequest()
        assertEquals("/v1/signatures/version", request.url.encodedPath)
        assertEquals(API_KEY, request.headers[ApiHeadersInterceptor.API_KEY_HEADER])
        assertEquals("BlackShield-Test/1", request.headers["User-Agent"])
    }

    @Test
    fun `never sends the API key to another host`() {
        MockWebServer().use { other ->
            other.start()
            other.enqueue(MockResponse.Builder().body("ok").build())
            val client = BlackShieldHttp.createClient(config)

            client.newCall(Request.Builder().url(other.url("/elsewhere")).build()).execute().close()

            assertNull(other.takeRequest().headers[ApiHeadersInterceptor.API_KEY_HEADER])
        }
    }

    @Test
    fun `does not follow redirects`() = runTest {
        server.enqueue(MockResponse.Builder().code(302).addHeader("Location", "https://evil.example/").build())

        val error =
            assertThrows(HttpException::class.java) { kotlinx.coroutines.runBlocking { api.signatureVersion() } }

        assertEquals(302, error.code())
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `decodes a gzip-compressed delta page transparently`() = runTest {
        val body =
            """{"since":3,"until":5,"latest_version":5,
               "additions":[{"hash":"${"a".repeat(
                64
            )}","algorithm":"sha256","family":null,"severity":"high","version":4}],
               "removals":[{"hash":"${"b".repeat(64)}","algorithm":"sha256","version":5}],
               "next_cursor":null,"unknown_field":true}"""
        server.enqueue(
            MockResponse.Builder().addHeader("Content-Encoding", "gzip").body(gzip(body)).build()
        )

        val page = api.signatureDelta(since = 3, limit = 100)

        assertEquals(5L, page.until)
        assertEquals("a".repeat(64), page.additions.single().hash)
        assertNull(page.additions.single().family)
        assertEquals("b".repeat(64), page.removals.single().hash)
        assertNull(page.nextCursor)
        val request = server.takeRequest()
        assertEquals("gzip", request.headers["Accept-Encoding"])
        assertEquals("3", request.url.queryParameter("since"))
        assertEquals("100", request.url.queryParameter("limit"))
        assertNull(request.url.queryParameter("cursor"))
    }

    @Test
    fun `snapshot is handed over still compressed`() = runTest {
        val compressed = gzip("{\"type\":\"header\"}\n")
        server.enqueue(
            MockResponse
                .Builder()
                .addHeader("Content-Encoding", "gzip")
                .addHeader("Content-Type", "application/x-ndjson")
                .body(compressed.copy())
                .build()
        )

        val response = api.signatureSnapshot()

        assertEquals("gzip", response.headers()["Content-Encoding"])
        assertEquals(compressed.readByteString(), response.body()!!.byteString())
    }

    @Test
    fun `reputation lookup accepts at most 100 hashes`() {
        assertThrows(IllegalArgumentException::class.java) { ReputationLookupRequest(List(101) { "a".repeat(64) }) }
        assertThrows(IllegalArgumentException::class.java) { ReputationLookupRequest(emptyList()) }
    }

    @Test
    fun `config toString does not reveal the API key`() {
        assertEquals(false, config.toString().contains(API_KEY))
    }

    private fun json(body: String) =
        MockResponse.Builder().addHeader("Content-Type", "application/json").body(body).build()

    private companion object {
        const val API_KEY = "bs_test-key-0123456789"

        fun gzip(text: String): Buffer {
            val buffer = Buffer()
            GzipSink(buffer).buffer().use { it.writeUtf8(text) }
            return buffer
        }
    }
}
