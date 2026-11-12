package com.blackshield.core.network

import com.blackshield.core.network.di.NetworkModule
import com.blackshield.core.network.model.HealthResponse
import org.junit.Assert.assertEquals
import org.junit.Test

class HealthResponseTest {
    private val json = NetworkModule.provideJson()

    @Test
    fun `decodes backend health payload and ignores unknown fields`() {
        val body = """{"status":"ok","version":"0.1.0","uptime_seconds":42}"""

        val response = json.decodeFromString(HealthResponse.serializer(), body)

        assertEquals(HealthResponse(status = "ok", version = "0.1.0"), response)
    }

    @Test
    fun `version is optional`() {
        val response = json.decodeFromString(HealthResponse.serializer(), """{"status":"ok"}""")

        assertEquals(null, response.version)
    }
}
