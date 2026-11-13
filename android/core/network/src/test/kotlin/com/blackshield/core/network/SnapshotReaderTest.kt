package com.blackshield.core.network

import okio.Buffer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class SnapshotReaderTest {
    private val hashA = "a".repeat(64)
    private val hashB = "b".repeat(32)

    @Test
    fun `reads header, signatures and verifies the end line`() {
        val reader =
            reader(
                HEADER_2,
                """{"hash":"$hashA","algorithm":"sha256","family":"Hydra","severity":"high"}""",
                """{"hash":"$hashB","algorithm":"md5","family":null,"severity":"critical"}""",
                """{"type":"end","version":9,"count":2}"""
            )

        assertEquals(SnapshotHeader(version = 9, count = 2), reader.readHeader())
        assertEquals(SnapshotSignature(hashA, "sha256", "Hydra", "high"), reader.next())
        assertEquals(SnapshotSignature(hashB, "md5", null, "critical"), reader.next())
        assertNull(reader.next())
        assertNull(reader.next())
    }

    @Test
    fun `missing end line is a truncated download`() {
        val reader = reader(HEADER_2, """{"hash":"$hashA","algorithm":"sha256","severity":"high"}""")
        reader.readHeader()
        reader.next()

        assertThrows(TruncatedSnapshotException::class.java) { reader.next() }
    }

    @Test
    fun `a line cut off mid-way is a truncated download`() {
        val buffer = Buffer().writeUtf8("$HEADER_2\n{\"hash\":\"$hashA\",\"algo")
        val reader = SnapshotReader(buffer)
        reader.readHeader()

        assertThrows(java.io.EOFException::class.java) { reader.next() }
    }

    @Test
    fun `end count that differs from the lines received is invalid`() {
        val reader =
            reader(
                HEADER_2,
                """{"hash":"$hashA","algorithm":"sha256","severity":"high"}""",
                """{"type":"end","version":9,"count":2}"""
            )
        reader.readHeader()
        reader.next()

        assertThrows(InvalidPayloadException::class.java) { reader.next() }
    }

    @Test
    fun `rejects malformed lines, unknown formats and trailing data`() {
        assertThrows(InvalidPayloadException::class.java) { reader("not json").readHeader() }
        assertThrows(InvalidPayloadException::class.java) {
            reader("""{"type":"header","format":2,"version":1,"count":0}""").readHeader()
        }
        assertThrows(InvalidPayloadException::class.java) {
            reader("""{"hash":"$hashA","algorithm":"sha256","severity":"high"}""").readHeader()
        }
        val trailing = reader(HEADER_0, """{"type":"end","version":9,"count":0}""", "{}")
        trailing.readHeader()
        assertThrows(InvalidPayloadException::class.java) { trailing.next() }
        val noHash = reader(HEADER_2, """{"algorithm":"sha256","severity":"high"}""")
        noHash.readHeader()
        assertThrows(InvalidPayloadException::class.java) { noHash.next() }
    }

    @Test
    fun `empty input is a truncated download`() {
        assertThrows(TruncatedSnapshotException::class.java) { SnapshotReader(Buffer()).readHeader() }
    }

    private fun reader(vararg lines: String) =
        SnapshotReader(Buffer().writeUtf8(lines.joinToString("\n", postfix = "\n")))

    private companion object {
        const val HEADER_2 =
            """{"type":"header","format":1,"version":9,"count":2,"created_at":"2026-11-13T09:00:00+00:00"}"""
        const val HEADER_0 = """{"type":"header","format":1,"version":9,"count":0}"""
    }
}
