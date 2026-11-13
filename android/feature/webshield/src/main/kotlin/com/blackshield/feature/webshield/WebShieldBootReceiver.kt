package com.blackshield.feature.webshield

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.blackshield.core.data.prefs.UserPreferencesRepository
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * Turns Web Shield back on after a reboot or an app update, if it was on. (If BlackShield is the
 * system's always-on VPN, the system starts the service itself.)
 */
@AndroidEntryPoint
class WebShieldBootReceiver : BroadcastReceiver() {
    @Inject lateinit var preferences: UserPreferencesRepository

    @Inject lateinit var controller: WebShieldController

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED && intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        val pending = goAsync()
        scope.launch {
            try {
                if (preferences.webShieldEnabled.first()) controller.start()
            } finally {
                pending.finish()
            }
        }
    }

    private companion object {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    }
}
