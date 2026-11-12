package com.blackshield.core.data.db

import com.blackshield.core.data.model.ScanReason
import org.junit.Assert.assertEquals
import org.junit.Test

class ConvertersTest {
    private val converters = Converters()

    @Test
    fun `reasons round-trip through JSON`() {
        val reasons =
            listOf(
                ScanReason(ScanReason.Code.KNOWN_MALWARE, "Test.Family (HIGH)", 90),
                ScanReason(ScanReason.Code.SIDELOADED, "Installer: unknown", 25)
            )

        val json = converters.reasonsToJson(reasons)

        assertEquals(reasons, converters.reasonsFromJson(json))
        assertEquals("[]", converters.reasonsToJson(emptyList()))
    }

    @Test
    fun `unknown JSON fields from newer versions are ignored`() {
        val json = """[{"code":"SIDELOADED","detail":"x","points":25,"addedInV3":true}]"""

        assertEquals(listOf(ScanReason(ScanReason.Code.SIDELOADED, "x", 25)), converters.reasonsFromJson(json))
    }
}
