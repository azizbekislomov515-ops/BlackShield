package com.blackshield.feature.webshield

import android.content.Context
import android.content.Intent
import android.net.VpnService
import com.blackshield.core.data.prefs.UserPreferencesRepository
import com.blackshield.feature.webshield.vpn.WebShieldVpnService
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton
import timber.log.Timber

/** Turns Web Shield on and off. The VPN permission itself is requested by the UI ([consentIntent]). */
@Singleton
class WebShieldController
@Inject
constructor(
    @param:ApplicationContext private val context: Context,
    private val preferences: UserPreferencesRepository,
    private val runtime: WebShieldRuntime
) {
    /** The system dialog to grant the VPN permission, or null when it is already granted. */
    fun consentIntent(): Intent? = VpnService.prepare(context)

    suspend fun enable() {
        preferences.setWebShieldEnabled(true)
        start()
    }

    suspend fun disable() {
        preferences.setWebShieldEnabled(false)
        stop()
    }

    /** Starts the VPN if permitted; otherwise reports [StopReason.NO_PERMISSION]. */
    fun start() {
        if (consentIntent() != null) {
            runtime.publish(WebShieldStatus.Stopped(StopReason.NO_PERMISSION))
            return
        }
        if (runtime.status.value is WebShieldStatus.On) return
        try {
            context.startService(
                Intent(context, WebShieldVpnService::class.java).setAction(WebShieldVpnService.ACTION_START)
            )
        } catch (e: IllegalStateException) {
            // Background start not allowed right now; the next foreground start or boot retries.
            Timber.w(e, "Could not start Web Shield")
        }
    }

    fun stop() {
        runtime.requestStop()
    }
}
