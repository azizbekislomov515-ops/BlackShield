package com.blackshield.app

import android.app.Notification
import android.app.NotificationManager
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.provider.MediaStore
import android.service.notification.StatusBarNotification
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.blackshield.core.data.model.Verdict
import com.blackshield.feature.protection.ProtectionEntryPoint
import com.blackshield.feature.protection.ProtectionNotifications
import dagger.hilt.android.EntryPointAccessors
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * End-to-end real-time protection in the real app process: installs the harmless EICAR test APK
 * (whose SHA-256 debug builds seed as malware) and checks that a warning and a ScanResult appear.
 */
@RunWith(AndroidJUnit4::class)
class RealtimeProtectionTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val protection = EntryPointAccessors.fromApplication(
        context.applicationContext,
        ProtectionEntryPoint::class.java
    )
    private val notifications = context.getSystemService(NotificationManager::class.java)

    @Before
    fun setUp() {
        // Streams the APK to `pm install` over stdin (executeShellCommandRwe, Android 12+).
        assumeTrue(Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
        shell("pm uninstall $EICAR_PACKAGE")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            shell("pm grant ${context.packageName} android.permission.POST_NOTIFICATIONS")
        }
        notifications.cancelAll()
        runBlocking { protection.controller().setEnabled(true) }
        waitFor("the protection service", 10_000) { protection.controller().isRunning.value }
        waitFor("the debug seed signatures", 10_000) {
            runBlocking { protection.signatures().findMatches(listOf(BuildConfig.EICAR_TEST_APK_SHA256)).isNotEmpty() }
        }
    }

    @After
    fun tearDown() {
        shell("pm uninstall $EICAR_PACKAGE")
        shell("rm -f $DOWNLOAD_PATH")
        runBlocking { protection.preferences().setWatchDownloads(false) }
        notifications.cancelAll()
    }

    @Test
    fun installingAFlaggedApkPostsAWarningWithinThreeSecondsAndSavesTheResult() {
        val apk = testApk()

        val output = shell("pm install -t -r -S ${apk.size}", stdin = apk)
        val installed = SystemClock.elapsedRealtime()
        assertTrue("install failed: $output", output.contains("Success"))

        val warning = waitFor("the threat notification", WARNING_DEADLINE_MILLIS) { threat("pkg:$EICAR_PACKAGE") }
        val latency = SystemClock.elapsedRealtime() - installed
        Log.i(TAG, "warning posted $latency ms after the install finished")
        assertTrue("warning took $latency ms", latency <= WARNING_DEADLINE_MILLIS)

        val actions = warning.notification.actions.map { it.title.toString() }
        assertEquals(listOf("Uninstall", "Ignore", "Details"), actions)
        assertEquals(ProtectionNotifications.THREAT_CHANNEL, warning.notification.channelId)

        val result = runBlocking { protection.scanResults().find(EICAR_PACKAGE) }
        assertNotNull("no ScanResult saved", result)
        assertEquals(Verdict.MALICIOUS, result?.verdict)
        assertEquals(BuildConfig.EICAR_TEST_APK_SHA256, result?.apkSha256)
    }

    @Test
    fun aFlaggedApkDownloadedToDownloadsIsCheckedBeforeInstall() {
        // MediaStore watching (Android 11+) with All files access, granted here the way a user would.
        assumeTrue(Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
        shell("appops set ${context.packageName} MANAGE_EXTERNAL_STORAGE allow")
        runBlocking { protection.preferences().setWatchDownloads(true) }
        SystemClock.sleep(WATCHER_START_MILLIS) // the service re-plans its watchers on the preference change

        // Save it the way browsers do on Android 10+: a pending MediaStore download, written, then published.
        val download = saveAsDownload(testApk())
        val published = SystemClock.elapsedRealtime()

        val warning = waitFor("the download warning", DOWNLOAD_DEADLINE_MILLIS) { threat("file:$DOWNLOAD_PATH") }
        Log.i(
            TAG,
            "download warning posted ${SystemClock.elapsedRealtime() - published} ms after the download completed"
        )
        context.contentResolver.delete(download, null, null)
        // A file is not installed, so there is no Uninstall; Details carries the result (FileResultCodecTest).
        assertEquals(listOf("Ignore", "Details"), warning.notification.actions.map { it.title.toString() })
        val extras = warning.notification.extras
        assertTrue(extras.getCharSequence(Notification.EXTRA_TITLE).toString().endsWith("is harmful"))
        assertTrue(
            extras.getCharSequence(Notification.EXTRA_BIG_TEXT).toString().contains("blackshield-eicar-test.apk")
        )
    }

    @androidx.annotation.RequiresApi(Build.VERSION_CODES.Q)
    private fun saveAsDownload(bytes: ByteArray): android.net.Uri {
        val resolver = context.contentResolver
        val values =
            android.content.ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, DOWNLOAD_NAME)
                put(MediaStore.Downloads.MIME_TYPE, "application/vnd.android.package-archive")
                put(MediaStore.Downloads.RELATIVE_PATH, "Download/")
                put(MediaStore.Downloads.IS_PENDING, 1)
            }
        val uri = checkNotNull(resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values))
        checkNotNull(resolver.openOutputStream(uri)).use { it.write(bytes) }
        resolver.update(
            uri,
            android.content.ContentValues().apply {
                put(MediaStore.Downloads.IS_PENDING, 0)
            },
            null,
            null
        )
        return uri
    }

    private fun threat(tag: String): StatusBarNotification? =
        notifications.activeNotifications.firstOrNull { it.tag == tag && it.id == ProtectionNotifications.THREAT_ID }

    private fun testApk(): ByteArray = instrumentation.context.assets.open("eicar-test.apk").use { it.readBytes() }

    /** Runs a shell command as the shell user; optional bytes go to its stdin. Returns stdout. */
    private fun shell(command: String, stdin: ByteArray? = null): String {
        val (out, input, err) = instrumentation.uiAutomation.executeShellCommandRwe(command)
        ParcelFileDescriptor.AutoCloseOutputStream(input).use { stream -> stdin?.let(stream::write) }
        ParcelFileDescriptor.AutoCloseInputStream(err).use { it.readBytes() }
        return ParcelFileDescriptor.AutoCloseInputStream(out).use { it.readBytes().decodeToString() }
    }

    private fun <T : Any> waitFor(what: String, timeoutMillis: Long, probe: () -> T?): T {
        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        while (SystemClock.elapsedRealtime() < deadline) {
            probe()?.takeUnless { it == false }?.let { return it }
            SystemClock.sleep(POLL_MILLIS)
        }
        throw AssertionError("timed out after $timeoutMillis ms waiting for $what")
    }

    private companion object {
        const val TAG = "RealtimeProtectionTest"
        const val EICAR_PACKAGE = "com.blackshield.testing.eicar"
        const val DOWNLOAD_NAME = "blackshield-eicar-test.apk"
        const val DOWNLOAD_PATH = "/storage/emulated/0/Download/$DOWNLOAD_NAME"
        const val WARNING_DEADLINE_MILLIS = 3_000L
        const val DOWNLOAD_DEADLINE_MILLIS = 15_000L
        const val WATCHER_START_MILLIS = 1_000L
        const val POLL_MILLIS = 50L
    }
}
