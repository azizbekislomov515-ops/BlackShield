package com.blackshield.feature.webshield.dns

import com.blackshield.feature.webshield.dns.IpPacketsTest.Companion.hex
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsMessagesTest {
    private fun parsed(message: ByteArray) = (DnsMessages.parse(message) as DnsParse.Query).query

    @Test
    fun `parses a standard query`() {
        val query = parsed(DnsMessages.query(0x1234, "Mail.Example.COM.", DnsMessages.TYPE_AAAA))
        assertEquals(0x1234, query.id)
        assertTrue(query.recursionDesired)
        assertEquals(DnsQuestion("mail.example.com", DnsMessages.TYPE_AAAA, DnsMessages.CLASS_IN), query.question)
    }

    @Test
    fun `parses a query with an EDNS OPT record after the question`() {
        // dig-style query for example.org with an OPT RR (arcount = 1).
        val message =
            hex(
                "abcd0120000100000000000107657861" + "6d706c65036f72670000010001" +
                    "0000291000000000000000"
            )
        val query = parsed(message)
        assertEquals("example.org", query.question.name)
        assertEquals(message.size - 11, query.questionEnd)
    }

    @Test
    fun `follows compression pointers and refuses loops`() {
        // name at 12 is a pointer to a name stored after the question section
        val message = hex("0001010000010000000000" + "00" + "c012" + "00010001" + "03777777076578616d706c6500")
        assertEquals("www.example", DnsMessages.readName(message, 12)!!.first)
        assertEquals(14, DnsMessages.readName(message, 12)!!.second)

        val loop = hex("000101000001000000000000c00c00010001")
        assertEquals(DnsParse.Refuse(1, DnsMessages.RCODE_FORMERR), DnsMessages.parse(loop))
    }

    @Test
    fun `refuses malformed names`() {
        val header = "000101000001000000000000"
        listOf(
            header + "40" + "61".repeat(64) + "00" + "00010001", // label of 64 bytes
            header + "0565786", // runs past the end
            header + "80" + "00010001", // reserved label type
            header + ("3f" + "61".repeat(63)).repeat(4) + "00" + "00010001", // name over 255 bytes
            header + "0161" + "00" + "0001" // question without class
        ).forEach { case ->
            assertEquals(case, DnsParse.Refuse(1, DnsMessages.RCODE_FORMERR), DnsMessages.parse(hex(case)))
        }
    }

    @Test
    fun `only single-question standard queries are filtered`() {
        assertEquals(DnsParse.Malformed, DnsMessages.parse(ByteArray(5)))
        val response = DnsMessages.query(7, "a.example").also { it[2] = 0x81.toByte() } // QR set
        assertEquals(DnsParse.Malformed, DnsMessages.parse(response))
        val notify = DnsMessages.query(7, "a.example").also { it[2] = 0x20 } // opcode 4
        assertEquals(DnsParse.Refuse(7, DnsMessages.RCODE_NOTIMP), DnsMessages.parse(notify))
        val two = DnsMessages.query(7, "a.example").also { IpPackets.put16(it, 4, 2) }
        assertEquals(DnsParse.Refuse(7, DnsMessages.RCODE_FORMERR), DnsMessages.parse(two))
    }

    @Test
    fun `nxdomain echoes id, question and RD, without answers or OPT`() {
        val raw = hex("abcd0120000100000000000107657861" + "6d706c65036f72670000010001" + "0000291000000000000000")
        val reply = DnsMessages.nxdomain(parsed(raw))
        assertEquals(0xabcd, IpPackets.u16(reply, 0))
        assertEquals(0x8183, IpPackets.u16(reply, 2)) // QR, RD, RA, NXDOMAIN
        assertEquals(listOf(1, 0, 0, 0), (4..10 step 2).map { IpPackets.u16(reply, it) })
        assertArrayEquals(raw.copyOfRange(12, raw.size - 11), reply.copyOfRange(12, reply.size))
        // A resolver can parse it back.
        assertEquals("example.org", DnsMessages.readName(reply, 12)!!.first)
    }

    @Test
    fun `sinkhole answers A with 0000 and AAAA with the unspecified address`() {
        val a = DnsMessages.sinkhole(parsed(DnsMessages.query(1, "evil.example")))
        assertEquals(0x8180, IpPackets.u16(a, 2))
        assertEquals(1, IpPackets.u16(a, 6))
        val answer = a.copyOfRange(a.size - 16, a.size)
        assertEquals(0xC00C, IpPackets.u16(answer, 0))
        assertEquals(DnsMessages.TYPE_A, IpPackets.u16(answer, 2))
        assertEquals(1, answer[9].toInt()) // TTL 1 s
        assertEquals(4, IpPackets.u16(answer, 10))
        assertArrayEquals(ByteArray(4), answer.copyOfRange(12, 16))

        val aaaa = DnsMessages.sinkhole(parsed(DnsMessages.query(1, "evil.example", DnsMessages.TYPE_AAAA)))
        assertArrayEquals(ByteArray(16), aaaa.copyOfRange(aaaa.size - 16, aaaa.size))

        val mx = DnsMessages.sinkhole(parsed(DnsMessages.query(1, "evil.example", 15)))
        assertEquals(0, IpPackets.u16(mx, 6)) // NODATA
    }

    @Test
    fun `servfail and refuse responses`() {
        assertEquals(0x8182, IpPackets.u16(DnsMessages.servfail(parsed(DnsMessages.query(9, "a.example"))), 2))
        val refused = DnsMessages.refuse(9, DnsMessages.RCODE_NOTIMP)
        assertEquals(12, refused.size)
        assertEquals(0x8084, IpPackets.u16(refused, 2))
    }

    @Test
    fun `a name of only the root is empty`() {
        assertEquals("" to 13, DnsMessages.readName(hex("00000000000000000000000000"), 12))
        assertNull(DnsMessages.readName(ByteArray(12), 12))
    }
}
