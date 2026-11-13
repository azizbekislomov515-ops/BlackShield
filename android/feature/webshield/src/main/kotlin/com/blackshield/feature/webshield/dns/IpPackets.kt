// IPv4/IPv6/UDP header offsets and sizes are fixed by the RFCs; parsing is a sequence of guard
// clauses (one early return per malformed case) and header builders take every header field.
@file:Suppress("MagicNumber", "ReturnCount", "LongParameterList")

package com.blackshield.feature.webshield.dns

/** A UDP datagram read from (or written to) the VPN interface. Addresses are 4 or 16 bytes. */
class UdpPacket(
    val ipVersion: Int,
    val source: ByteArray,
    val destination: ByteArray,
    val sourcePort: Int,
    val destinationPort: Int,
    val payload: ByteArray
)

/**
 * Parses and builds the raw IPv4/IPv6 + UDP packets of the VPN interface (RFC 791, 8200, 768).
 * Only what DNS needs: unfragmented UDP. Everything else parses to null and is dropped.
 */
object IpPackets {
    const val PROTOCOL_UDP = 17
    private const val IPV4_HEADER = 20
    private const val IPV6_HEADER = 40
    private const val UDP_HEADER = 8
    private const val DEFAULT_TTL = 64

    // IPv6 extension headers that may precede UDP. Fragments are not handled: stub resolvers
    // never fragment DNS over UDP.
    private const val HOP_BY_HOP = 0
    private const val ROUTING = 43
    private const val DESTINATION_OPTIONS = 60

    fun parseUdp(packet: ByteArray, length: Int = packet.size): UdpPacket? {
        if (length < 1 || length > packet.size) return null
        return when (packet[0].toInt() ushr 4) {
            4 -> parseIpv4(packet, length)
            6 -> parseIpv6(packet, length)
            else -> null
        }
    }

    private fun parseIpv4(p: ByteArray, length: Int): UdpPacket? {
        if (length < IPV4_HEADER) return null
        val headerLength = (p[0].toInt() and 0x0F) * 4
        val totalLength = u16(p, 2)
        val fragment = u16(p, 6)
        val moreFragments = fragment and 0x2000 != 0
        val offset = fragment and 0x1FFF
        val valid =
            headerLength >= IPV4_HEADER &&
                totalLength in headerLength + UDP_HEADER..length &&
                !moreFragments &&
                offset == 0 &&
                (p[9].toInt() and 0xFF) == PROTOCOL_UDP
        if (!valid) return null
        return parseUdp(4, p.copyOfRange(12, 16), p.copyOfRange(16, 20), p, headerLength, totalLength)
    }

    private fun parseIpv6(p: ByteArray, length: Int): UdpPacket? {
        if (length < IPV6_HEADER) return null
        val end = IPV6_HEADER + u16(p, 4)
        if (end > length) return null
        var next = p[6].toInt() and 0xFF
        var offset = IPV6_HEADER
        while (next == HOP_BY_HOP || next == ROUTING || next == DESTINATION_OPTIONS) {
            if (offset + 2 > end) return null
            next = p[offset].toInt() and 0xFF
            offset += ((p[offset + 1].toInt() and 0xFF) + 1) * 8
        }
        if (next != PROTOCOL_UDP || offset + UDP_HEADER > end) return null
        return parseUdp(6, p.copyOfRange(8, 24), p.copyOfRange(24, 40), p, offset, end)
    }

    private fun parseUdp(version: Int, src: ByteArray, dst: ByteArray, p: ByteArray, start: Int, end: Int): UdpPacket? {
        val udpLength = u16(p, start + 4)
        if (udpLength < UDP_HEADER || start + udpLength > end) return null
        return UdpPacket(
            ipVersion = version,
            source = src,
            destination = dst,
            sourcePort = u16(p, start),
            destinationPort = u16(p, start + 2),
            payload = p.copyOfRange(start + UDP_HEADER, start + udpLength)
        )
    }

    /** A complete IP packet carrying [payload] in one UDP datagram, with valid checksums. */
    fun buildUdp(
        ipVersion: Int,
        source: ByteArray,
        destination: ByteArray,
        sourcePort: Int,
        destinationPort: Int,
        payload: ByteArray
    ): ByteArray {
        require(
            (ipVersion == 4 && source.size == 4 && destination.size == 4) ||
                (ipVersion == 6 && source.size == 16 && destination.size == 16)
        ) {
            "address size does not match IPv$ipVersion"
        }
        val udpLength = UDP_HEADER + payload.size
        val header = if (ipVersion == 4) IPV4_HEADER else IPV6_HEADER
        val packet = ByteArray(header + udpLength)
        if (ipVersion == 4) {
            packet[0] = 0x45
            put16(packet, 2, packet.size)
            put16(packet, 6, 0x4000) // don't fragment
            packet[8] = DEFAULT_TTL.toByte()
            packet[9] = PROTOCOL_UDP.toByte()
            source.copyInto(packet, 12)
            destination.copyInto(packet, 16)
            put16(packet, 10, checksum(packet, 0, IPV4_HEADER, 0))
        } else {
            packet[0] = 0x60
            put16(packet, 4, udpLength)
            packet[6] = PROTOCOL_UDP.toByte()
            packet[7] = DEFAULT_TTL.toByte()
            source.copyInto(packet, 8)
            destination.copyInto(packet, 24)
        }
        put16(packet, header, sourcePort)
        put16(packet, header + 2, destinationPort)
        put16(packet, header + 4, udpLength)
        payload.copyInto(packet, header + UDP_HEADER)
        put16(packet, header + 6, udpChecksum(packet, ipVersion, header, udpLength))
        return packet
    }

    /** The UDP checksum over the pseudo-header and datagram; 0 is sent as 0xFFFF (RFC 768). */
    fun udpChecksum(packet: ByteArray, ipVersion: Int, udpStart: Int, udpLength: Int): Int {
        val pseudo =
            if (ipVersion == 4) {
                sum(packet, 12, 8) + PROTOCOL_UDP + udpLength
            } else {
                sum(packet, 8, 32) + PROTOCOL_UDP + udpLength
            }
        val saved = u16(packet, udpStart + 6)
        put16(packet, udpStart + 6, 0)
        val result = checksum(packet, udpStart, udpLength, pseudo)
        put16(packet, udpStart + 6, saved)
        return if (result == 0) 0xFFFF else result
    }

    /** Internet checksum (RFC 1071) of [length] bytes at [start], plus an initial [sum]. */
    fun checksum(data: ByteArray, start: Int, length: Int, initial: Long): Int {
        var sum = initial + sum(data, start, length)
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.inv().toInt() and 0xFFFF
    }

    private fun sum(data: ByteArray, start: Int, length: Int): Long {
        var sum = 0L
        var i = start
        while (i + 1 < start + length) {
            sum += u16(data, i)
            i += 2
        }
        if (i < start + length) sum += (data[i].toInt() and 0xFF) shl 8
        return sum
    }

    internal fun u16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

    internal fun put16(data: ByteArray, offset: Int, value: Int) {
        data[offset] = (value ushr 8).toByte()
        data[offset + 1] = value.toByte()
    }
}
