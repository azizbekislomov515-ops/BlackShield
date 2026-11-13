package com.blackshield.feature.protection

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import dagger.hilt.android.EntryPointAccessors
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import timber.log.Timber

private val receiverScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

private fun Context.protection(): ProtectionEntryPoint =
    EntryPointAccessors.fromApplication(applicationContext, ProtectionEntryPoint::class.java)

/** Runs [block] off the main thread, keeping the broadcast alive until it finishes (goAsync). */
private fun BroadcastReceiver.async(block: suspend () -> Unit) {
    val pending = goAsync()
    receiverScope.launch {
        try {
            block()
        } finally {
            pending.finish()
        }
    }
}

/**
 * Restores real-time protection after a reboot or an update of BlackShield itself. Both broadcasts
 * are exempt from the background foreground-service start restrictions (Android 12+), and
 * `specialUse` services may start from BOOT_COMPLETED (Android 15 only blocks dataSync, camera,
 * media and phone types there).
 */
class ProtectionBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED && intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        async {
            val protection = context.protection()
            if (protection.preferences().realTimeProtectionEnabled.first()) {
                Timber.i("Restoring real-time protection after %s", intent.action)
                protection.controller().start()
            }
        }
    }
}

/** Notification actions that do not open an activity: "Ignore" and "Turn off". Not exported. */
class AlertActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val protection = context.protection()
        when (intent.action) {
            ProtectionIntents.ACTION_IGNORE -> async {
                intent.getStringExtra(ProtectionIntents.EXTRA_SHA256)?.let { protection.state().ignore(it) }
                intent.getStringExtra(ProtectionIntents.EXTRA_KEY)?.let { protection.notifications().cancelThreat(it) }
            }

            ProtectionIntents.ACTION_TURN_OFF -> async { protection.controller().setEnabled(false) }
        }
    }
}
