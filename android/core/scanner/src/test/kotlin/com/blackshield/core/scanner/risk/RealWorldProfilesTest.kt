package com.blackshield.core.scanner.risk

import com.blackshield.core.data.model.Verdict
import com.blackshield.core.scanner.analysis.AppProfile
import com.blackshield.core.scanner.analysis.LauncherState
import com.blackshield.core.scanner.risk.TestProfiles.BIND_DEVICE_ADMIN
import com.blackshield.core.scanner.risk.TestProfiles.DANGEROUS_12
import com.blackshield.core.scanner.risk.TestProfiles.INSTALL_PACKAGES
import com.blackshield.core.scanner.risk.TestProfiles.NOW
import com.blackshield.core.scanner.risk.TestProfiles.OVERLAY
import com.blackshield.core.scanner.risk.TestProfiles.PACKAGE_INSTALLER
import com.blackshield.core.scanner.risk.TestProfiles.READ_SMS
import com.blackshield.core.scanner.risk.TestProfiles.RECEIVE_SMS
import com.blackshield.core.scanner.risk.TestProfiles.SEND_SMS
import com.blackshield.core.scanner.risk.TestProfiles.accessibilityService
import com.blackshield.core.scanner.risk.TestProfiles.activity
import com.blackshield.core.scanner.risk.TestProfiles.aospTestKeyCert
import com.blackshield.core.scanner.risk.TestProfiles.debugCert
import com.blackshield.core.scanner.risk.TestProfiles.deviceAdminReceiver
import com.blackshield.core.scanner.risk.TestProfiles.profile
import com.blackshield.core.scanner.risk.TestProfiles.service
import com.blackshield.core.scanner.risk.TestProfiles.smsReceiver
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The shipped rules against realistic profiles. False positives: popular legitimate apps whose
 * permissions look alarming on paper must stay CLEAN (or, when sideloaded with banker-like powers,
 * SUSPICIOUS at most). True positives: typical malware shapes must not stay CLEAN.
 * Permission sets are representative of each app's published manifest, not exact copies.
 */
class RealWorldProfilesTest {
    private val engine = TestProfiles.engine()

    private fun assertVerdict(expected: Verdict, profile: AppProfile) {
        val result = engine.evaluate(profile, NOW)
        assertEquals(
            "${profile.packageName}: score ${result.score}, findings ${result.findings.map { it.ruleId to it.points }}",
            expected,
            result.verdict
        )
    }

    // --- Popular legitimate apps (false-positive guard) --------------------------------------------

    @Test
    fun `Google Messages from Play - default SMS app`() = assertVerdict(
        Verdict.CLEAN,
        profile(
            packageName = "com.google.android.apps.messaging",
            permissions = setOf(READ_SMS, RECEIVE_SMS, SEND_SMS) + DANGEROUS_12.take(6),
            components = listOf(
                activity("com.google.android.apps.messaging.ui.ConversationListActivity"),
                smsReceiver("com.google.android.apps.messaging.receiver.SmsDeliverReceiver")
            )
        )
    )

    @Test
    fun `WhatsApp from Play - many sensitive permissions and overlay`() = assertVerdict(
        Verdict.CLEAN,
        profile(packageName = "com.whatsapp", permissions = DANGEROUS_12 + setOf(RECEIVE_SMS, OVERLAY))
    )

    @Test
    fun `Tasker from Play - SMS, accessibility, overlay and device admin, all enabled`() =
        assertVerdict(Verdict.CLEAN, tasker(TestProfiles.PLAY))

    @Test
    fun `Tasker sideloaded from its website is suspicious, not malicious`() =
        assertVerdict(Verdict.SUSPICIOUS, tasker(PACKAGE_INSTALLER))

    @Test
    fun `Bitwarden from Play - accessibility autofill with overlay`() = assertVerdict(
        Verdict.CLEAN,
        profile(
            packageName = "com.x8bit.bitwarden",
            permissions = setOf(OVERLAY),
            components = listOf(
                activity("com.x8bit.bitwarden.MainActivity"),
                accessibilityService("com.x8bit.bitwarden.Accessibility.AccessibilityService")
            ),
            accessibilityEnabled = true
        )
    )

    @Test
    fun `Intune Company Portal from Play - active device administrator`() = assertVerdict(
        Verdict.CLEAN,
        profile(
            packageName = "com.microsoft.windowsintune.companyportal",
            components = listOf(
                activity("com.microsoft.windowsintune.companyportal.views.SplashActivity"),
                deviceAdminReceiver("com.microsoft.omadm.client.PolicyManagerReceiver")
            ),
            deviceAdminActive = true
        )
    )

    @Test
    fun `Gboard from Play - no launcher icon`() = assertVerdict(
        Verdict.CLEAN,
        profile(
            packageName = "com.google.android.inputmethod.latin",
            launcher = LauncherState.NONE_DECLARED,
            launcherActivities = emptyList()
        )
    )

    @Test
    fun `Firefox from F-Droid`() = assertVerdict(
        Verdict.CLEAN,
        profile(
            packageName = "org.mozilla.fennec_fdroid",
            installer = "org.fdroid.fdroid",
            permissions = DANGEROUS_12.take(5).toSet()
        )
    )

    @Test
    fun `F-Droid client sideloaded today - an app store that installs apps`() = assertVerdict(
        Verdict.CLEAN,
        profile(
            packageName = "org.fdroid.fdroid",
            installer = PACKAGE_INSTALLER,
            initiating = "com.android.chrome",
            permissions = setOf(INSTALL_PACKAGES),
            installedAt =
                NOW - TimeUnit.HOURS.toMillis(1)
        )
    )

    @Test
    fun `packed app from a vendor store`() = assertVerdict(
        Verdict.CLEAN,
        profile(
            packageName = "com.example.cn",
            installer = "com.huawei.appmarket",
            applicationClass = "com.tencent.StubShell.TxAppEntry"
        )
    )

    @Test
    fun `sideloaded game with ordinary permissions`() = assertVerdict(
        Verdict.CLEAN,
        profile(
            packageName = "com.example.game",
            installer = PACKAGE_INSTALLER,
            permissions = setOf("android.permission.INTERNET", "android.permission.VIBRATE")
        )
    )

    @Test
    fun `BlackShield's own debug build installed with adb`() = assertVerdict(
        Verdict.CLEAN,
        profile(
            packageName = "com.blackshield.app.debug",
            installer = null,
            debuggable = true,
            certificates = listOf(debugCert()),
            installedAt =
                NOW - TimeUnit.HOURS.toMillis(1)
        )
    )

    @Test
    fun `standard system apps are never flagged, whatever they hold`() {
        val systemApps =
            listOf(
                profile(
                    packageName = "com.android.settings",
                    system = true,
                    installer = null,
                    permissions =
                        DANGEROUS_12 + setOf(INSTALL_PACKAGES, BIND_DEVICE_ADMIN)
                ),
                profile(
                    packageName = "com.android.phone",
                    system = true,
                    installer = null,
                    permissions = setOf(READ_SMS, RECEIVE_SMS, SEND_SMS),
                    launcher = LauncherState.NONE_DECLARED
                ),
                profile(
                    packageName = "com.google.android.gms",
                    system = true,
                    installer = TestProfiles.PLAY,
                    permissions =
                        DANGEROUS_12 + setOf(READ_SMS, OVERLAY),
                    components = listOf(service("a.b"), service("a.c"), service("a.d"))
                ),
                // An updated system app: installed by Play, still FLAG_SYSTEM.
                profile(packageName = "com.android.chrome", system = true, installer = TestProfiles.PLAY),
                profile(
                    packageName = "com.android.shell",
                    system = true,
                    installer = null,
                    certificates = listOf(aospTestKeyCert()),
                    launcher = LauncherState.NONE_DECLARED
                )
            )

        systemApps.forEach { app ->
            val result = engine.evaluate(app, NOW)
            assertEquals(app.packageName, Verdict.CLEAN, result.verdict)
            assertEquals(app.packageName, Exemption.SYSTEM_APP, result.exemption)
        }
    }

    // --- Malware shapes (true positives) -----------------------------------------------------------

    @Test
    fun `banking trojan that hid its icon is malicious`() {
        val banker =
            profile(
                packageName = "com.flashlight.pro",
                installer = PACKAGE_INSTALLER,
                initiating = "com.android.chrome",
                permissions = setOf(READ_SMS, RECEIVE_SMS, SEND_SMS, OVERLAY),
                components = listOf(
                    activity("com.flashlight.pro.Main"),
                    accessibilityService("com.flashlight.pro.Watcher"),
                    smsReceiver("com.flashlight.pro.SmsIn")
                ),
                launcher = LauncherState.HIDDEN,
                accessibilityEnabled = true,
                installedAt = NOW - TimeUnit.DAYS.toMillis(1)
            )
        assertVerdict(Verdict.MALICIOUS, banker)

        val result = engine.evaluate(banker, NOW)
        assertTrue(
            "capabilities are capped at 50",
            result.findings.filter { it.group == "capability" }.sumOf { it.points } <= 50
        )
    }

    @Test
    fun `banking trojan capabilities without concealment are suspicious`() = assertVerdict(
        Verdict.SUSPICIOUS,
        profile(
            installer = PACKAGE_INSTALLER,
            permissions = setOf(RECEIVE_SMS, OVERLAY),
            components = listOf(activity("com.x.Main"), accessibilityService("com.x.Svc"))
        )
    )

    @Test
    fun `packed SMS stealer targeting an old SDK is malicious`() = assertVerdict(
        Verdict.MALICIOUS,
        profile(
            installer = PACKAGE_INSTALLER,
            targetSdk = 22,
            permissions = setOf(READ_SMS, RECEIVE_SMS),
            applicationClass = "com.stub.StubApp",
            nativeLibraries = setOf("libjiagu.so"),
            installedAt = NOW - TimeUnit.HOURS.toMillis(3)
        )
    )

    @Test
    fun `fake system update signed with the AOSP test key is malicious`() = assertVerdict(
        Verdict.MALICIOUS,
        profile(
            packageName = "com.android.systemupdate.service",
            installer = PACKAGE_INSTALLER,
            certificates = listOf(aospTestKeyCert()),
            components = listOf(
                activity("com.android.systemupdate.service.Main"),
                deviceAdminReceiver("com.android.systemupdate.service.Admin")
            )
        )
    )

    @Test
    fun `obfuscated dropper with no icon is suspicious`() = assertVerdict(
        Verdict.SUSPICIOUS,
        profile(
            installer = PACKAGE_INSTALLER,
            permissions = setOf(INSTALL_PACKAGES),
            components = listOf(service("a.b"), service("a.c"), service("b.a")),
            launcher = LauncherState.NONE_DECLARED,
            launcherActivities = emptyList()
        )
    )

    private fun tasker(installer: String) = profile(
        packageName = "net.dinglisch.android.taskerm",
        installer = installer,
        permissions = DANGEROUS_12 + setOf(READ_SMS, RECEIVE_SMS, SEND_SMS, OVERLAY),
        components =
            listOf(
                activity("net.dinglisch.android.taskerm.Tasker"),
                accessibilityService("net.dinglisch.android.taskerm.MyAccessibilityService"),
                deviceAdminReceiver("net.dinglisch.android.taskerm.MyDeviceAdminReceiver"),
                smsReceiver("net.dinglisch.android.taskerm.ReceiverStaticAlwaysOn")
            ),
        accessibilityEnabled = true,
        deviceAdminActive = true
    )
}
