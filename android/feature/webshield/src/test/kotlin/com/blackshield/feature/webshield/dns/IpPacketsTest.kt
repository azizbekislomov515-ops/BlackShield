package com.blackshield.feature.webshield.dns

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Crafted IPv4/IPv6 UDP packets; the hex vectors were built independently (Python struct). */
class IpPacketsTest {
    private val v4Query =
        hex(
            "4500003900004000401169d20a6fde010a6fde029c4000350025b0aa" +
                "123401000001000000000000076578616d706c6503636f6d0000010001"
        )
    private val v6Query =
        hex(
            "6000000000291140fd00b1a55e1d00000000000000000001fd00b1a55e1d00000000000000000002" +
                "c350003500291ec0beef0100000100000000000003577777074578616d706c6503434f4d00001c0001"
        )
    private val src4 = byteArrayOf(10, 111, 222.toByte(), 1)
    private val dst4 = byteArrayOf(10, 111, 222.toByte(), 2)

    @Test
    fun `parses an IPv4 UDP packet`() {
        val packet = IpPackets.parseUdp(v4Query)!!
        assertEquals(4, packet.ipVersion)
        assertArrayEquals(src4, packet.source)
        assertArrayEquals(dst4, packet.destination)
        assertEquals(40000, packet.sourcePort)
        assertEquals(53, packet.destinationPort)
        assertEquals("example.com", (DnsMessages.parse(packet.payload) as DnsParse.Query).query.question.name)
    }

    @Test
    fun `parses an IPv6 UDP packet`() {
        val packet = IpPackets.parseUdp(v6Query)!!
        assertEquals(6, packet.ipVersion)
        assertEquals(16, packet.source.size)
        assertEquals(50000, packet.sourcePort)
        val question = (DnsMessages.parse(packet.payload) as DnsParse.Query).query.question
        assertEquals(DnsQuestion("www.example.com", DnsMessages.TYPE_AAAA, DnsMessages.CLASS_IN), question)
    }

    @Test
    fun `builds byte-identical packets with correct checksums`() {
        val payload = IpPackets.parseUdp(v4Query)!!.payload
        assertArrayEquals(v4Query, IpPackets.buildUdp(4, src4, dst4, 40000, 53, payload))
        val v6 = IpPackets.parseUdp(v6Query)!!
        assertArrayEquals(v6Query, IpPackets.buildUdp(6, v6.source, v6.destination, 50000, 53, v6.payload))
    }

    @Test
    fun `checksums verify to zero over the whole header`() {
        val reply = IpPackets.buildUdp(4, dst4, src4, 53, 40000, ByteArray(33) { it.toByte() }) // odd length
        assertEquals(0, IpPackets.checksum(reply, 0, 20, 0))
        val udpLength = reply.size - 20
        val pseudo = (sumWords(reply, 12, 8) + 17 + udpLength)
        assertEquals(0, IpPackets.checksum(reply, 20, udpLength, pseudo))
    }

    @Test
    fun `IPv6 extension headers before UDP are skipped`() {
        // Insert an 8-byte hop-by-hop header (next header = UDP).
        val withExt =
            v6Query.copyOfRange(0, 40) + byteArrayOf(17, 0, 1, 4, 0, 0, 0, 0) + v6Query.copyOfRange(40, v6Query.size)
        withExt[6] = 0 // next header: hop-by-hop
        IpPackets.put16(withExt, 4, IpPackets.u16(v6Query, 4) + 8)
        assertEquals(50000, IpPackets.parseUdp(withExt)!!.sourcePort)
    }

    @Test
    fun `rejects what is not one whole UDP datagram`() {
        assertNull(IpPackets.parseUdp(ByteArray(0)))
        assertNull(IpPackets.parseUdp(v4Query.copyOf(25))) // truncated
        assertNull(IpPackets.parseUdp(v4Query.copyOf().also { it[9] = 6 })) // TCP
        assertNull(IpPackets.parseUdp(v4Query.copyOf().also { it[6] = 0x20 })) // more fragments
        assertNull(IpPackets.parseUdp(v4Query.copyOf().also { it[7] = 1 })) // fragment offset
        assertNull(IpPackets.parseUdp(v4Query.copyOf().also { it[0] = 0x44 })) // IHL 4
        assertNull(IpPackets.parseUdp(v4Query.copyOf().also { IpPackets.put16(it, 24, 200) })) // UDP length too big
        assertNull(IpPackets.parseUdp(v6Query.copyOf().also { it[6] = 44 })) // fragment header
        assertNull(IpPackets.parseUdp(v6Query.copyOf().also { it[0] = 0x50 })) // unknown version
        assertNull(IpPackets.parseUdp(v4Query, v4Query.size + 1))
    }

    private fun sumWords(data: ByteArray, start: Int, length: Int): Long =
        (start until start + length step 2).sumOf { IpPackets.u16(data, it).toLong() }

    companion object {
        fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}
