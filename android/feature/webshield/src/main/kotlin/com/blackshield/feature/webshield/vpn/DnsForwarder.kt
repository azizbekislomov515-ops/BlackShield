package com.blackshield.feature.webshield.vpn

import com.blackshield.feature.webshield.dns.IpPackets
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.SocketTimeoutException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Sends an allowed query, byte for byte, to the user's real resolver and returns its answer.
 * Each query gets its own socket (bound to the real network and protected from the VPN), so
 * answers can never be mixed up between queries. Servers are tried in order with a short timeout.
 */
class DnsForwarder(
    private val upstream: () -> Upstream,
    private val protect: (DatagramSocket) -> Unit,
    private val timeoutMillis: Int = DEFAULT_TIMEOUT_MILLIS
) {
    suspend fun forward(query: ByteArray): ByteArray? = withContext(Dispatchers.IO) {
        val target = upstream()
        for (server in target.servers.take(MAX_SERVERS)) {
            val answer =
                try {
                    DatagramSocket().use { socket ->
                        target.network?.bindSocket(socket)
                        protect(socket)
                        socket.soTimeout = timeoutMillis
                        socket.send(DatagramPacket(query, query.size, server, DnsPacketHandler.DNS_PORT))
                        receiveMatching(socket, IpPackets.u16(query, 0))
                    }
                } catch (_: SocketTimeoutException) {
                    null
                } catch (_: IOException) {
                    null // network gone mid-query (Wi-Fi/mobile switch): try the next server
                } catch (_: SecurityException) {
                    null
                }
            if (answer != null) return@withContext answer
        }
        null
    }

    /** Skips stray datagrams with another id until the timeout. */
    private fun receiveMatching(socket: DatagramSocket, id: Int): ByteArray {
        val buffer = ByteArray(MAX_RESPONSE)
        while (true) {
            val packet = DatagramPacket(buffer, buffer.size)
            socket.receive(packet)
            if (packet.length >= 2 && IpPackets.u16(buffer, 0) == id) return buffer.copyOf(packet.length)
        }
    }

    companion object {
        const val DEFAULT_TIMEOUT_MILLIS = 2_000
        private const val MAX_SERVERS = 3
        private const val MAX_RESPONSE = 65_535
    }
}
