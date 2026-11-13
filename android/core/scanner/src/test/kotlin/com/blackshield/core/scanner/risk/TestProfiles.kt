package com.blackshield.core.scanner.risk

import com.blackshield.core.scanner.analysis.AppComponent
import com.blackshield.core.scanner.analysis.AppProfile
import com.blackshield.core.scanner.analysis.LauncherState
import com.blackshield.core.scanner.analysis.SigningCertificate
import com.blackshield.core.scanner.analysis.manifest.ComponentKind
import com.blackshield.core.scanner.analysis.manifest.IntentFilterSpec
import java.io.File
import java.util.concurrent.TimeUnit

/** Shared test data: the shipped rules and an [AppProfile] builder. */
object TestProfiles {
    /** The rules file exactly as shipped in the app (Gradle runs unit tests from the module directory). */
    val SHIPPED_RULES_JSON: String by lazy { File("src/main/assets/risk/risk_rules.json").readText() }
    val SHIPPED_RULES: RiskRules by lazy { RiskRulesParser.parse(SHIPPED_RULES_JSON) }

    const val NOW = 1_763_035_200_000L // 2025-11-13T12:00:00Z
    val LONG_AGO = NOW - TimeUnit.DAYS.toMillis(400)

    const val PLAY = "com.android.vending"
    const val PACKAGE_INSTALLER = "com.google.android.packageinstaller"

    const val READ_SMS = "android.permission.READ_SMS"
    const val RECEIVE_SMS = "android.permission.RECEIVE_SMS"
    const val SEND_SMS = "android.permission.SEND_SMS"
    const val OVERLAY = "android.permission.SYSTEM_ALERT_WINDOW"
    const val INSTALL_PACKAGES = "android.permission.REQUEST_INSTALL_PACKAGES"
    const val BIND_ACCESSIBILITY = "android.permission.BIND_ACCESSIBILITY_SERVICE"
    const val BIND_DEVICE_ADMIN = "android.permission.BIND_DEVICE_ADMIN"
    const val SMS_RECEIVED = "android.provider.Telephony.SMS_RECEIVED"

    val DANGEROUS_12 =
        listOf(
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.READ_CALL_LOG",
            "android.permission.READ_PHONE_STATE",
            "android.permission.CALL_PHONE",
            "android.permission.READ_CALENDAR",
            "android.permission.BODY_SENSORS",
            "android.permission.READ_MEDIA_IMAGES"
        ).toSet()

    fun engine(rules: RiskRules = SHIPPED_RULES) = RiskEngine(rules)

    /** Defaults describe an ordinary app from Google Play with a launcher icon, installed long ago. */
    @Suppress("LongParameterList") // test-data builder: every parameter has a default
    fun profile(
        packageName: String = "com.example.app",
        installer: String? = PLAY,
        initiating: String? = null,
        system: Boolean = false,
        debuggable: Boolean = false,
        targetSdk: Int = 35,
        installedAt: Long = LONG_AGO,
        permissions: Set<String> = emptySet(),
        dangerous: Set<String> = permissions.filterTo(HashSet()) {
            it in DANGEROUS_12 ||
                it in setOf(READ_SMS, RECEIVE_SMS, SEND_SMS)
        },
        components: List<AppComponent> = listOf(activity("$packageName.MainActivity")),
        launcher: LauncherState = LauncherState.VISIBLE,
        launcherActivities: List<String> = listOf("$packageName.MainActivity"),
        certificates: List<SigningCertificate> = listOf(releaseCert()),
        applicationClass: String? = null,
        nativeLibraries: Set<String> = emptySet(),
        accessibilityEnabled: Boolean = false,
        deviceAdminActive: Boolean = false
    ) = AppProfile(
        packageName = packageName,
        label = packageName.substringAfterLast('.'),
        isSystemApp = system,
        isDebuggable = debuggable,
        installerPackage = installer,
        initiatingPackage = initiating,
        targetSdk = targetSdk,
        firstInstallTime = installedAt,
        requestedPermissions = permissions,
        grantedPermissions = permissions,
        dangerousPermissions = dangerous,
        components = components,
        launcher = launcher,
        launcherActivities = launcherActivities,
        signingCertificates = certificates,
        applicationClass = applicationClass,
        nativeLibraries = nativeLibraries,
        accessibilityServiceEnabled = accessibilityEnabled,
        deviceAdminActive = deviceAdminActive
    )

    fun activity(name: String, launcher: Boolean = true) = AppComponent(
        ComponentKind.ACTIVITY,
        name,
        exported = launcher,
        intentFilters =
            if (launcher) {
                listOf(
                    IntentFilterSpec(listOf("android.intent.action.MAIN"), listOf("android.intent.category.LAUNCHER"))
                )
            } else {
                emptyList()
            }
    )

    fun accessibilityService(name: String) = AppComponent(
        ComponentKind.SERVICE,
        name,
        exported = true,
        permission = BIND_ACCESSIBILITY,
        intentFilters = listOf(IntentFilterSpec(listOf("android.accessibilityservice.AccessibilityService")))
    )

    fun deviceAdminReceiver(name: String) = AppComponent(
        ComponentKind.RECEIVER,
        name,
        exported = true,
        permission = BIND_DEVICE_ADMIN,
        intentFilters = listOf(IntentFilterSpec(listOf("android.app.action.DEVICE_ADMIN_ENABLED")))
    )

    fun smsReceiver(name: String) = AppComponent(
        ComponentKind.RECEIVER,
        name,
        exported = true,
        intentFilters = listOf(IntentFilterSpec(listOf(SMS_RECEIVED), priority = 999))
    )

    fun service(name: String) = AppComponent(ComponentKind.SERVICE, name, exported = false)

    fun releaseCert(sha: Char = 'a') = SigningCertificate(
        sha.toString().repeat(64),
        "CN=Example, O=Example",
        "CN=Example, O=Example",
        true,
        false,
        false
    )

    fun debugCert() = SigningCertificate(
        "d".repeat(64),
        "CN=Android Debug, O=Android, C=US",
        "CN=Android Debug, O=Android, C=US",
        selfSigned = true,
        debug = true,
        aospTestKey = false
    )

    fun aospTestKeyCert() = SigningCertificate(
        "e".repeat(64),
        "EMAILADDRESS=android@android.com, CN=Android, OU=Android, O=Android, L=Mountain View, ST=California, C=US",
        "EMAILADDRESS=android@android.com, CN=Android, OU=Android, O=Android, L=Mountain View, ST=California, C=US",
        selfSigned = true,
        debug = false,
        aospTestKey = true
    )
}
