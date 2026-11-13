package com.blackshield.feature.protection

import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import androidx.core.net.toUri
import com.blackshield.core.data.prefs.UserPreferencesRepository
import com.blackshield.feature.protection.logic.DownloadsWatch
import com.blackshield.feature.protection.logic.PackageCatchUp
import com.blackshield.feature.protection.logic.WatchPlan
import com.blackshield.feature.protection.logic.WatchPlanner
import com.blackshield.feature.protection.watch.ApkWatcher
import com.blackshield.feature.protection.watch.FileObserverDownloadsWatcher
import com.blackshield.feature.protection.watch.MediaStoreDownloadsWatcher
import com.blackshield.feature.protection.watch.SafFolderWatcher
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.launch
import timber.log.Timber

/**
 * Real-time protection: scans every app as soon as it is installed or updated, and new APK files
 * in watched folders, and warns about anything not clean.
 *
 * Why a foreground service: since Android 8, PACKAGE_ADDED / PACKAGE_REPLACED are not delivered to
 * manifest-registered receivers. Only a receiver registered at runtime, in a running process,
 * gets them; the service keeps that process alive. Type `specialUse` (Android 14+): `dataSync` is
 * limited to 6 hours a day and may not start from BOOT_COMPLETED on Android 15+.
 *
 * It keeps running when the app is swiped away (not stopWithTask) and is START_STICKY, so the
 * system restarts it if the process is killed. [ProtectionBootReceiver] starts it after a reboot
 * or app update. Installs missed while it was not running are caught up with getChangedPackages().
 */
@AndroidEntryPoint
class RealtimeProtectionService : Service() {
    @Inject lateinit var engine: ProtectionEngine

    @Inject lateinit var notifications: ProtectionNotifications

    @Inject lateinit var preferences: UserPreferencesRepository

    @Inject lateinit var state: ProtectionStateStore

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val refresh = MutableStateFlow(0)
    private var watchers: List<ApkWatcher> = emptyList()
    private var watchingFiles = false

    private val packageReceiver =
        object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                val pkg = intent.data?.schemeSpecificPart ?: return
                val replacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)
                when (intent.action) {
                    Intent.ACTION_PACKAGE_ADDED, Intent.ACTION_PACKAGE_REPLACED -> engine.onPackageChanged(pkg)
                    Intent.ACTION_PACKAGE_REMOVED -> if (!replacing) engine.onPackageRemoved(pkg)
                }
                scope.launch { saveCursor() }
            }
        }

    override fun onCreate() {
        super.onCreate()
        notifications.createChannels()
        goForeground()
        engine.attach(scope)
        ContextCompat.registerReceiver(
            this,
            packageReceiver,
            IntentFilter().apply {
                addAction(Intent.ACTION_PACKAGE_ADDED)
                addAction(Intent.ACTION_PACKAGE_REPLACED)
                addAction(Intent.ACTION_PACKAGE_REMOVED)
                addDataScheme("package")
            },
            // Protected system broadcasts still arrive; other apps cannot send to this receiver.
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
        running.value = true
        scope.launch { catchUp() }
        scope.launch {
            combine(preferences.watchDownloads, preferences.watchedFolders, refresh) { downloads, folders, _ ->
                WatchPlanner.plan(
                    Build.VERSION.SDK_INT,
                    downloads,
                    DeviceGrants.hasAllFilesAccess(),
                    DeviceGrants.hasLegacyRead(this@RealtimeProtectionService),
                    folders
                )
            }.distinctUntilChanged().collect(::apply)
        }
        Timber.i("Real-time protection started")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Re-read storage grants: the user may have just allowed All files access.
        if (intent?.action == ACTION_REFRESH) refresh.value++
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        unregisterReceiver(packageReceiver)
        watchers.forEach(ApkWatcher::stop)
        watchers = emptyList()
        running.value = false
        scope.cancel()
        Timber.i("Real-time protection stopped")
        super.onDestroy()
    }

    private fun goForeground() {
        val type = if (Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.UPSIDE_DOWN_CAKE
        ) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        ServiceCompat.startForeground(
            this,
            ProtectionNotifications.STATUS_ID,
            notifications.statusNotification(watchingFiles),
            type
        )
    }

    private fun apply(plan: WatchPlan) {
        watchers.forEach(ApkWatcher::stop)
        watchers =
            buildList {
                when (plan.downloads) {
                    DownloadsWatch.MEDIA_STORE -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        add(MediaStoreDownloadsWatcher(this@RealtimeProtectionService, scope, state, engine::onApkFile))
                    }

                    DownloadsWatch.FILE_OBSERVER -> add(FileObserverDownloadsWatcher(engine::onApkFile))

                    DownloadsWatch.OFF, DownloadsWatch.MISSING_PERMISSION -> Unit
                }
                plan.folders.forEach {
                    add(SafFolderWatcher(this@RealtimeProtectionService, scope, it.toUri(), engine::onApkFile))
                }
            }
        watchers.forEach(ApkWatcher::start)
        watchingFiles = watchers.isNotEmpty()
        goForeground() // update the notification text
        Timber.i("Watching: downloads=%s, %d folders", plan.downloads, plan.folders.size)
    }

    /** Scans packages installed or updated while protection was not running. */
    private suspend fun catchUp() {
        val start = PackageCatchUp.startSequence(state.packageCursor(), DeviceGrants.bootCount(this))
        val changes = packageManager.getChangedPackages(start ?: 0)
        if (start != null) changes?.packageNames?.forEach(engine::onPackageChanged)
        state.setPackageCursor(
            PackageCatchUp.Cursor(DeviceGrants.bootCount(this), changes?.sequenceNumber ?: start ?: 0)
        )
    }

    private suspend fun saveCursor() {
        val cursor = state.packageCursor() ?: return
        packageManager.getChangedPackages(cursor.sequence)?.let {
            state.setPackageCursor(cursor.copy(sequence = it.sequenceNumber))
        }
    }

    companion object {
        const val ACTION_REFRESH = "com.blackshield.action.REFRESH_PROTECTION"

        private val running = MutableStateFlow(false)

        /** Whether the service is running in this process. */
        val isRunning: StateFlow<Boolean> = running.asStateFlow()
    }
}
