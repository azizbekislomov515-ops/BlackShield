package com.blackshield.feature.webshield.vpn

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import android.os.Looper
import java.net.InetAddress
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** The real network under the VPN and its DNS servers (the user's resolver: router, carrier, or their own). */
data class Upstream(
    val network: Network? = null,
    val servers: List<InetAddress> = emptyList(),
    /** Private DNS in strict mode ("hostname"): the system talks DNS-over-TLS itself and bypasses Web Shield. */
    val privateDnsServer: String? = null,
    val metered: Boolean = false
)

/**
 * Follows the best real (non-VPN) internet network: Wi-Fi, mobile data... and switches with it, so
 * after a Wi-Fi/mobile change the next query already goes to the new network's resolver. (The
 * default-network callback cannot be used: it reports our own VPN, even though this app is
 * excluded from it.) [onChange] lets the service tell the system which network the VPN runs over
 * (`setUnderlyingNetworks`), so metering and transport are right.
 */
class UpstreamTracker(private val connectivity: ConnectivityManager, private val onChange: (Upstream) -> Unit) {
    private val state = MutableStateFlow(Upstream())
    val upstream: StateFlow<Upstream> = state.asStateFlow()

    private val callback =
        object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                connectivity.getLinkProperties(network)?.let { update(network, it) }
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                update(network, linkProperties)
            }

            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                if (network == state.value.network) {
                    val metered = !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
                    if (metered != state.value.metered) publish(state.value.copy(metered = metered))
                }
            }

            override fun onLost(network: Network) {
                if (network == state.value.network) publish(Upstream())
            }
        }

    fun start() {
        val request =
            NetworkRequest
                .Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            connectivity.registerBestMatchingNetworkCallback(request, callback, Handler(Looper.getMainLooper()))
        } else {
            // Satisfied by the current default network; it never brings up another one.
            connectivity.requestNetwork(request, callback)
        }
    }

    fun stop() {
        runCatching { connectivity.unregisterNetworkCallback(callback) }
    }

    private fun update(network: Network, properties: LinkProperties) {
        val metered =
            connectivity.getNetworkCapabilities(
                network
            )?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) ==
                false
        publish(
            Upstream(
                network = network,
                servers = properties.dnsServers.toList(),
                privateDnsServer = if (Build.VERSION.SDK_INT >=
                    Build.VERSION_CODES.P
                ) {
                    properties.privateDnsServerName
                } else {
                    null
                },
                metered = metered
            )
        )
    }

    private fun publish(next: Upstream) {
        if (next == state.value) return
        state.value = next
        onChange(next)
    }
}
