package com.blackshield.feature.webshield.vpn

import com.blackshield.feature.webshield.blocklist.DnsFilter
import com.blackshield.feature.webshield.blocklist.DomainMatch
import com.blackshield.feature.webshield.blocklist.FilterDecision
import com.blackshield.feature.webshield.dns.DnsMessages
import com.blackshield.feature.webshield.dns.DnsParse
import com.blackshield.feature.webshield.dns.IpPackets
import com.blackshield.feature.webshield.dns.UdpPacket

/** How a blocked lookup is answered. */
enum class BlockMode {
    /** "No such domain": works for every record type; browsers show "site can't be reached". */
    NXDOMAIN,

    /** 0.0.0.0 / :: : the connection fails at once. */
    SINKHOLE
}

/**
 * Turns one packet from the VPN interface into the packet to write back: a block answer built
 * here, the upstream resolver's answer for an allowed query, or nothing (dropped). Free of Android
 * types so it is unit-tested with crafted packets.
 */
class DnsPacketHandler(
    private val filter: DnsFilter,
    private val mode: BlockMode = BlockMode.NXDOMAIN,
    private val onBlocked: (name: String, match: DomainMatch) -> Unit = { _, _ -> }
) {
    suspend fun handle(packet: UdpPacket, forward: suspend (ByteArray) -> ByteArray?): ByteArray? {
        val reply = if (packet.destinationPort == DNS_PORT) reply(packet.payload, forward) else null
        // Answer from the address and port the query went to.
        return reply?.let {
            IpPackets.buildUdp(
                packet.ipVersion,
                packet.destination,
                packet.source,
                packet.destinationPort,
                packet.sourcePort,
                it
            )
        }
    }

    /** The DNS answer for [message], or null to drop it. */
    private suspend fun reply(message: ByteArray, forward: suspend (ByteArray) -> ByteArray?): ByteArray? =
        when (val parsed = DnsMessages.parse(message)) {
            DnsParse.Malformed -> null

            is DnsParse.Refuse -> DnsMessages.refuse(parsed.id, parsed.rcode)

            is DnsParse.Query -> {
                val query = parsed.query
                when (val decision = filter.decide(query.question.name)) {
                    FilterDecision.Allow -> forward(message)?.takeIf { sameId(it, query.id) }
                        ?: DnsMessages.servfail(query)

                    is FilterDecision.Block -> {
                        onBlocked(query.question.name, decision.match)
                        if (mode == BlockMode.NXDOMAIN) DnsMessages.nxdomain(query) else DnsMessages.sinkhole(query)
                    }
                }
            }
        }

    /** An upstream answer must carry the query's id; anything else is dropped as a spoofing attempt. */
    private fun sameId(response: ByteArray, id: Int): Boolean = response.size >= 2 && IpPackets.u16(response, 0) == id

    companion object {
        const val DNS_PORT = 53
    }
}
