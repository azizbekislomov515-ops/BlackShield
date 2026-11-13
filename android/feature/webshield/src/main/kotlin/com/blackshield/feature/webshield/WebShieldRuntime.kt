package com.blackshield.feature.webshield

import com.blackshield.feature.webshield.blocklist.DnsFilter
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow

/** What Web Shield is doing right now, for the screen and the quick settings tile. */
sealed interface WebShieldStatus {
    data object Off : WebShieldStatus

    data object Starting : WebShieldStatus

    data class On(
        val blockedDomains: Int,
        /** DNS servers of the real network; 0 means lookups fail until a network is back. */
        val upstreamServers: Int,
        /** Private DNS (strict) is on: the system resolves names itself and Web Shield sees nothing. */
        val privateDnsBypass: String?,
        val alwaysOn: Boolean
    ) : WebShieldStatus

    data class Stopped(val reason: StopReason) : WebShieldStatus
}

enum class StopReason {
    /** The VPN permission is missing (never granted, or revoked in settings). */
    NO_PERMISSION,

    /** Another VPN app started, or the user disconnected the VPN in system settings. */
    REVOKED,

    /** The system refused to create the VPN interface (e.g. another app is the always-on VPN). */
    ESTABLISH_FAILED
}

/**
 * State shared by the VPN service, the controller, the tile and the notification actions (all in
 * the app process). The [filter] holds the live blocklist and allowances.
 */
@Singleton
class WebShieldRuntime
@Inject
constructor() {
    val filter = DnsFilter()

    private val mutableStatus = MutableStateFlow<WebShieldStatus>(WebShieldStatus.Off)
    val status: StateFlow<WebShieldStatus> = mutableStatus.asStateFlow()

    private val stops = MutableSharedFlow<Unit>(extraBufferCapacity = 1, onBufferOverflow = BufferOverflow.DROP_OLDEST)

    /** The running service collects this and shuts down cleanly. */
    val stopRequests: SharedFlow<Unit> = stops.asSharedFlow()

    fun publish(status: WebShieldStatus) {
        mutableStatus.value = status
    }

    fun requestStop() {
        stops.tryEmit(Unit)
    }
}
