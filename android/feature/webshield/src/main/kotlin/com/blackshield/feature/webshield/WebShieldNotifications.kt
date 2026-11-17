package com.blackshield.feature.webshield

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.blackshield.core.data.AppEntry
import com.blackshield.core.data.model.DomainCategory
import dagger.hilt.android.qualifiers.ApplicationContext
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

/**
 * "Blocked page" notifications, with "Allow once" and "Always allow". Rate-limited: one per
 * domain per [PER_DOMAIN_MILLIS], and at most one every [MIN_GAP_MILLIS] overall, so a page that
 * retries a blocked name in a loop cannot flood the shade (or drain the battery).
 */
@Singleton
class WebShieldNotifications
@Inject
constructor(@param:ApplicationContext private val context: Context) {
    private val lastShown = ConcurrentHashMap<String, Long>()

    @Volatile
    private var lastAny = 0L

    @Volatile
    private var channelsCreated = false

    /** Idempotent; called before the first notification of the process. */
    fun createChannels() {
        if (channelsCreated) return
        channelsCreated = true
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        manager.createNotificationChannel(
            NotificationChannel(
                BLOCKED_CHANNEL,
                context.getString(R.string.webshield_channel_blocked),
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply { description = context.getString(R.string.webshield_channel_blocked_description) }
        )
        manager.createNotificationChannel(
            NotificationChannel(
                STATUS_CHANNEL,
                context.getString(R.string.webshield_channel_status),
                NotificationManager.IMPORTANCE_LOW
            )
        )
    }

    fun canPost(): Boolean = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
    } else {
        NotificationManagerCompat.from(context).areNotificationsEnabled()
    }

    fun blocked(listed: String, category: DomainCategory, now: Long = System.currentTimeMillis()) {
        if (!canPost()) return
        val previous = lastShown[listed]
        if ((previous != null && now - previous < PER_DOMAIN_MILLIS) || now - lastAny < MIN_GAP_MILLIS) return
        lastShown[listed] = now
        lastAny = now
        createChannels()
        if (lastShown.size > MAX_REMEMBERED) lastShown.entries.removeIf { now - it.value >= PER_DOMAIN_MILLIS }

        val id = NOTIFICATION_BASE + (listed.hashCode() and NOTIFICATION_MASK)
        val title =
            context.getString(
                if (category ==
                    DomainCategory.PHISHING
                ) {
                    R.string.webshield_blocked_phishing
                } else {
                    R.string.webshield_blocked_malware
                }
            )
        val notification =
            NotificationCompat
                .Builder(context, BLOCKED_CHANNEL)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentTitle(title)
                .setContentText(listed)
                .setStyle(
                    NotificationCompat.BigTextStyle().bigText(
                        context.getString(R.string.webshield_blocked_body, listed)
                    )
                )
                .setCategory(NotificationCompat.CATEGORY_STATUS)
                .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
                .setAutoCancel(true)
                .setContentIntent(openApp())
                .addAction(
                    0,
                    context.getString(R.string.webshield_allow_once),
                    action(BlockedPageReceiver.ACTION_ALLOW_ONCE, listed, id)
                )
                .addAction(
                    0,
                    context.getString(R.string.webshield_always_allow),
                    action(BlockedPageReceiver.ACTION_ALWAYS_ALLOW, listed, id)
                )
                .build()
        @Suppress("MissingPermission") // checked by canPost()
        NotificationManagerCompat.from(context).notify(id, notification)
    }

    /** Another VPN took over, or the user disconnected Web Shield in system settings. */
    fun revoked() {
        if (!canPost()) return
        createChannels()
        val notification =
            NotificationCompat
                .Builder(context, STATUS_CHANNEL)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentTitle(context.getString(R.string.webshield_revoked_title))
                .setContentText(context.getString(R.string.webshield_revoked_body))
                .setStyle(NotificationCompat.BigTextStyle().bigText(context.getString(R.string.webshield_revoked_body)))
                .setAutoCancel(true)
                .setContentIntent(openApp())
                .build()
        @Suppress("MissingPermission") // checked by canPost()
        NotificationManagerCompat.from(context).notify(REVOKED_ID, notification)
    }

    fun cancel(id: Int) = NotificationManagerCompat.from(context).cancel(id)

    private fun openApp(): PendingIntent = PendingIntent.getActivity(
        context,
        0,
        AppEntry.intent(context).putExtra(EXTRA_SHOW_WEB_SHIELD, true),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
    )

    private fun action(action: String, domain: String, notificationId: Int): PendingIntent = PendingIntent.getBroadcast(
        context,
        notificationId * 2 + if (action == BlockedPageReceiver.ACTION_ALLOW_ONCE) 0 else 1,
        Intent(context, BlockedPageReceiver::class.java)
            .setAction(action)
            .putExtra(BlockedPageReceiver.EXTRA_DOMAIN, domain)
            .putExtra(BlockedPageReceiver.EXTRA_NOTIFICATION_ID, notificationId),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
    )

    companion object {
        const val BLOCKED_CHANNEL = "web_shield_blocked"
        const val STATUS_CHANNEL = "web_shield_status"
        const val EXTRA_SHOW_WEB_SHIELD = "com.blackshield.webshield.SHOW"
        private const val REVOKED_ID = 3001
        private const val NOTIFICATION_BASE = 3100
        private const val NOTIFICATION_MASK = 0xFFFF
        private const val PER_DOMAIN_MILLIS = 10 * 60_000L
        private const val MIN_GAP_MILLIS = 3_000L
        private const val MAX_REMEMBERED = 256
    }
}
