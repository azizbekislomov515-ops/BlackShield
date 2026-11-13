package com.blackshield.feature.protection

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.blackshield.core.data.model.Verdict
import com.blackshield.feature.protection.logic.ThreatAlert
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/** Intent contract between notifications and the app's main activity. */
object ProtectionIntents {
    /** Open the scan screen with this package's result. */
    const val EXTRA_SHOW_PACKAGE = "com.blackshield.extra.SHOW_PACKAGE"

    /** Show this file result ([FileResultCodec]). */
    const val EXTRA_FILE_RESULT = "com.blackshield.extra.FILE_RESULT"

    internal const val ACTION_IGNORE = "com.blackshield.action.IGNORE_ALERT"
    internal const val ACTION_TURN_OFF = "com.blackshield.action.TURN_OFF_PROTECTION"
    internal const val EXTRA_KEY = "key"
    internal const val EXTRA_SHA256 = "sha256"
}

@Singleton
class ProtectionNotifications
@Inject
constructor(@ApplicationContext private val context: Context) {
    private val manager = NotificationManagerCompat.from(context)

    fun createChannels() {
        val system = context.getSystemService(NotificationManager::class.java)
        system.createNotificationChannel(
            NotificationChannel(
                STATUS_CHANNEL,
                context.getString(R.string.channel_status_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = context.getString(R.string.channel_status_description)
                setShowBadge(false)
            }
        )
        system.createNotificationChannel(
            NotificationChannel(
                THREAT_CHANNEL,
                context.getString(R.string.channel_threats_name),
                NotificationManager.IMPORTANCE_HIGH
            ).apply { description = context.getString(R.string.channel_threats_description) }
        )
    }

    /** POST_NOTIFICATIONS granted (Android 13+) and notifications not switched off. */
    fun canPost(): Boolean {
        val granted =
            Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
                ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) ==
                PackageManager.PERMISSION_GRANTED
        return granted && manager.areNotificationsEnabled()
    }

    fun threatChannelEnabled(): Boolean =
        manager.getNotificationChannel(THREAT_CHANNEL)?.importance != NotificationManager.IMPORTANCE_NONE

    /** The ongoing notification of the foreground service. */
    fun statusNotification(watchingFiles: Boolean): Notification = NotificationCompat
        .Builder(context, STATUS_CHANNEL)
        .setSmallIcon(R.drawable.ic_stat_protection)
        .setContentTitle(context.getString(R.string.status_title))
        .setContentText(context.getString(if (watchingFiles) R.string.status_text_files else R.string.status_text_apps))
        .setOngoing(true)
        .setShowWhen(false)
        .setPriority(NotificationCompat.PRIORITY_LOW)
        .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
        .setContentIntent(openApp(STATUS_ID, Intent()))
        .addAction(
            0,
            context.getString(R.string.action_turn_off),
            broadcast(STATUS_ID, ProtectionIntents.ACTION_TURN_OFF)
        )
        .build()

    /**
     * Posts (or updates) the warning for an app or file. For a file, [encodedFileResult] rides in
     * the Details intent, since files have no stored result to look up.
     */
    fun showThreat(alert: ThreatAlert, encodedFileResult: String? = null) {
        if (!canPost()) return
        val request = alert.key.hashCode()
        val details =
            Intent().apply {
                encodedFileResult?.let { putExtra(ProtectionIntents.EXTRA_FILE_RESULT, it) }
                    ?: alert.packageName?.let { putExtra(ProtectionIntents.EXTRA_SHOW_PACKAGE, it) }
            }
        val title =
            context.getString(
                if (alert.verdict ==
                    Verdict.MALICIOUS
                ) {
                    R.string.threat_title_malicious
                } else {
                    R.string.threat_title_suspicious
                },
                alert.appName
            )
        val summary =
            alert.fileName?.let { context.getString(R.string.threat_text_file, it) }
                ?: context.getString(R.string.threat_text_app)
        val bigText = (listOf(summary) + alert.topReasons.map { "• $it" }).joinToString("\n")
        val builder =
            NotificationCompat
                .Builder(context, THREAT_CHANNEL)
                .setSmallIcon(R.drawable.ic_stat_protection)
                .setContentTitle(title)
                .setContentText(alert.topReasons.firstOrNull() ?: summary)
                .setStyle(NotificationCompat.BigTextStyle().bigText(bigText))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_RECOMMENDATION)
                .setAutoCancel(true)
                .setContentIntent(openApp(request, details))
        // Only installed apps can be uninstalled; a file is not installed yet.
        if (alert.fileName == null && alert.packageName != null) {
            builder.addAction(0, context.getString(R.string.action_uninstall), uninstall(request, alert.packageName))
        }
        builder
            .addAction(0, context.getString(R.string.action_ignore), ignore(request, alert))
            .addAction(0, context.getString(R.string.action_details), openApp(request + DETAILS_OFFSET, details))
        @Suppress("MissingPermission") // checked by canPost()
        manager.notify(alert.key, THREAT_ID, builder.build())
    }

    fun cancelThreat(key: String) = manager.cancel(key, THREAT_ID)

    private fun openApp(request: Int, extras: Intent): PendingIntent {
        val launch =
            (context.packageManager.getLaunchIntentForPackage(context.packageName) ?: Intent())
                .putExtras(extras)
                .addFlags(
                    Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
                )
        return PendingIntent.getActivity(context, request, launch, FLAGS)
    }

    /** The system uninstall dialog (needs REQUEST_DELETE_PACKAGES); the user confirms there. */
    private fun uninstall(request: Int, packageName: String): PendingIntent = PendingIntent.getActivity(
        context,
        request + UNINSTALL_OFFSET,
        Intent(
            Intent.ACTION_DELETE,
            Uri.fromParts("package", packageName, null)
        ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        FLAGS
    )

    private fun ignore(request: Int, alert: ThreatAlert): PendingIntent {
        val intent =
            Intent(context, AlertActionReceiver::class.java)
                .setAction(ProtectionIntents.ACTION_IGNORE)
                .putExtra(ProtectionIntents.EXTRA_KEY, alert.key)
                .putExtra(ProtectionIntents.EXTRA_SHA256, alert.sha256)
        return PendingIntent.getBroadcast(context, request + IGNORE_OFFSET, intent, FLAGS)
    }

    private fun broadcast(request: Int, action: String): PendingIntent = PendingIntent.getBroadcast(
        context,
        request,
        Intent(context, AlertActionReceiver::class.java).setAction(action),
        FLAGS
    )

    companion object {
        const val STATUS_CHANNEL = "protection_status"
        const val THREAT_CHANNEL = "threats"
        const val STATUS_ID = 1001
        const val THREAT_ID = 2001

        // Distinct PendingIntent request codes per alert and action.
        private const val DETAILS_OFFSET = 1
        private const val UNINSTALL_OFFSET = 2
        private const val IGNORE_OFFSET = 3
        private const val FLAGS = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
    }
}
