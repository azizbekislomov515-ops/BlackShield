package com.blackshield.feature.webshield

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.blackshield.core.data.repository.WebAllowListRepository
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/** The actions of a "Blocked page" notification. Not exported: only our PendingIntents reach it. */
@AndroidEntryPoint
class BlockedPageReceiver : BroadcastReceiver() {
    @Inject lateinit var runtime: WebShieldRuntime

    @Inject lateinit var allowList: WebAllowListRepository

    @Inject lateinit var notifications: WebShieldNotifications

    override fun onReceive(context: Context, intent: Intent) {
        val domain = intent.getStringExtra(EXTRA_DOMAIN) ?: return
        notifications.cancel(intent.getIntExtra(EXTRA_NOTIFICATION_ID, 0))
        when (intent.action) {
            // Takes effect on the next lookup: block answers carry no TTL, so nothing is cached.
            ACTION_ALLOW_ONCE -> runtime.filter.allowTemporarily(domain, ALLOW_ONCE_MILLIS)

            ACTION_ALWAYS_ALLOW -> {
                runtime.filter.allowTemporarily(domain, ALLOW_ONCE_MILLIS) // until the allowlist reloads
                val pending = goAsync()
                scope.launch {
                    try {
                        allowList.allow(domain)
                    } finally {
                        pending.finish()
                    }
                }
            }
        }
    }

    companion object {
        const val ACTION_ALLOW_ONCE = "com.blackshield.webshield.ALLOW_ONCE"
        const val ACTION_ALWAYS_ALLOW = "com.blackshield.webshield.ALWAYS_ALLOW"
        const val EXTRA_DOMAIN = "domain"
        const val EXTRA_NOTIFICATION_ID = "notification_id"

        /** "Once" = long enough to load the page and what it pulls in, short enough to expire unnoticed. */
        const val ALLOW_ONCE_MILLIS = 10 * 60_000L

        private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    }
}
