package com.blackshield.app

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.blackshield.app.security.AppIntegrity
import com.blackshield.app.security.IntegrityScreen
import com.blackshield.app.ui.AppNavigationBar
import com.blackshield.app.ui.Overlay
import com.blackshield.app.ui.OverlayHost
import com.blackshield.app.ui.Tab
import com.blackshield.core.data.AppEntry
import com.blackshield.core.data.model.ScanResult
import com.blackshield.core.data.prefs.AppSettingsRepository
import com.blackshield.core.data.prefs.ThemeMode
import com.blackshield.core.data.prefs.UserPreferencesRepository
import com.blackshield.core.designsystem.theme.BlackShieldTheme
import com.blackshield.feature.home.HomeNavigation
import com.blackshield.feature.home.HomeRoute
import com.blackshield.feature.home.onboarding.OnboardingRoute
import com.blackshield.feature.protection.FileResultCodec
import com.blackshield.feature.protection.ProtectionController
import com.blackshield.feature.protection.ProtectionIntents
import com.blackshield.feature.scan.ScanResultDetailsSheet
import com.blackshield.feature.scan.ScanRoute
import com.blackshield.feature.scan.ScanViewModel
import com.blackshield.feature.scan.schedule.ScheduledScanWorker
import com.blackshield.feature.settings.SettingsRoute
import com.blackshield.feature.threats.ThreatsRoute
import com.blackshield.feature.webshield.WebShieldController
import com.blackshield.feature.webshield.WebShieldNotifications
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

@AndroidEntryPoint
class MainActivity : ComponentActivity() {
    @Inject lateinit var preferences: UserPreferencesRepository

    @Inject lateinit var settings: AppSettingsRepository

    @Inject lateinit var protection: ProtectionController

    @Inject lateinit var webShield: WebShieldController

    /** What a notification asked to show. */
    private val deepLink = MutableStateFlow<DeepLink?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        if (AppIntegrity.problems(this).isNotEmpty()) {
            // A modified copy must not look like it protects anyone: no services, no app, just the warning.
            setContent { BlackShieldTheme(darkTheme = isSystemInDarkTheme()) { IntegrityScreen() } }
            return
        }
        handle(intent)
        // Keep the protection service in line with the setting. Starting a foreground service is
        // allowed here because the activity is visible; boot and updates are handled by a receiver.
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                preferences.realTimeProtectionEnabled.distinctUntilChanged().collect { enabled ->
                    if (enabled) protection.start() else protection.stop()
                }
            }
        }
        // Web Shield normally keeps running on its own (the system holds the VPN); this restarts it
        // if it was on but stopped, e.g. after the app was updated.
        lifecycleScope.launch {
            if (preferences.webShieldEnabled.first()) webShield.start()
        }
        setContent {
            val theme by settings.themeMode.collectAsStateWithLifecycle(initialValue = ThemeMode.SYSTEM)
            val onboarded by settings.onboardingCompleted.collectAsStateWithLifecycle(initialValue = null)
            val dark =
                when (theme) {
                    ThemeMode.SYSTEM -> isSystemInDarkTheme()
                    ThemeMode.LIGHT -> false
                    ThemeMode.DARK -> true
                }
            BlackShieldTheme(darkTheme = dark) {
                when (onboarded) {
                    null -> Box(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background))
                    false -> OnboardingRoute(onDone = {})
                    true -> BlackShieldApp(deepLink)
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handle(intent)
    }

    override fun onResume() {
        super.onResume()
        protection.refresh() // storage access may have changed in system settings
    }

    private fun handle(intent: Intent?) {
        // Extras are trusted only from the app's own PendingIntents, which target the non-exported alias.
        // The exported launcher entry ignores them, so other apps cannot make BlackShield show a forged result.
        if (intent?.component?.className != AppEntry.INTERNAL_ENTRY) return
        val link =
            when {
                intent.getBooleanExtra(WebShieldNotifications.EXTRA_SHOW_WEB_SHIELD, false) -> DeepLink.WebShield

                intent.getBooleanExtra(ScheduledScanWorker.EXTRA_SHOW_THREATS, false) -> DeepLink.Threats

                else ->
                    FileResultCodec.decode(
                        intent.getStringExtra(ProtectionIntents.EXTRA_FILE_RESULT)
                    )?.let(DeepLink::File)
                        ?: intent.getStringExtra(ProtectionIntents.EXTRA_SHOW_PACKAGE)?.let(DeepLink::Package)
            }
        link?.let { deepLink.value = it }
    }
}

sealed interface DeepLink {
    data class Package(val packageName: String) : DeepLink

    data class File(val result: ScanResult) : DeepLink

    data object WebShield : DeepLink

    data object Threats : DeepLink
}

@Composable
private fun BlackShieldApp(deepLink: MutableStateFlow<DeepLink?>) {
    var tab by rememberSaveable { mutableStateOf(Tab.HOME) }
    val overlays = remember { mutableStateListOf<Overlay>() }
    var shownFile by remember { mutableStateOf<ScanResult?>(null) }
    val scan: ScanViewModel = hiltViewModel()
    val open = { overlay: Overlay -> if (overlays.lastOrNull() != overlay) overlays += overlay }
    val showTab = { target: Tab ->
        overlays.clear()
        tab = target
    }

    DeepLinks(
        deepLink,
        onPackage = {
            showTab(Tab.SCAN)
            scan.showDetails(it)
        },
        onFile = { shownFile = it },
        onWebShield = { open(Overlay.WEB_SHIELD) },
        onThreats = { showTab(Tab.THREATS) }
    )

    BackHandler(enabled = overlays.isNotEmpty() || tab != Tab.HOME) {
        if (overlays.isNotEmpty()) overlays.removeAt(overlays.lastIndex) else tab = Tab.HOME
    }

    val top = overlays.lastOrNull()
    if (top != null) {
        OverlayHost(top, onBack = { overlays.removeAt(overlays.lastIndex) })
    } else {
        Scaffold(bottomBar = { AppNavigationBar(tab, onSelect = { tab = it }) }) { innerPadding ->
            // Each screen has its own Scaffold; consuming the insets here stops it adding them twice.
            val content = Modifier.fillMaxSize().padding(innerPadding).consumeWindowInsets(innerPadding)
            TabContent(tab, scan, onTab = { tab = it }, onOpen = open, modifier = content)
        }
    }

    shownFile?.let { file ->
        ScanResultDetailsSheet(result = file, trusted = false, onTrustedChange = {
        }, onDismiss = { shownFile = null }, showTrust = false)
    }
}

@Composable
private fun DeepLinks(
    deepLink: MutableStateFlow<DeepLink?>,
    onPackage: (String) -> Unit,
    onFile: (ScanResult) -> Unit,
    onWebShield: () -> Unit,
    onThreats: () -> Unit
) {
    LaunchedEffect(Unit) {
        deepLink.collect { link ->
            when (link) {
                is DeepLink.Package -> onPackage(link.packageName)
                is DeepLink.File -> onFile(link.result)
                DeepLink.WebShield -> onWebShield()
                DeepLink.Threats -> onThreats()
                null -> Unit
            }
            deepLink.value = null
        }
    }
}

@Composable
private fun TabContent(
    tab: Tab,
    scan: ScanViewModel,
    onTab: (Tab) -> Unit,
    onOpen: (Overlay) -> Unit,
    modifier: Modifier
) {
    when (tab) {
        Tab.HOME ->
            HomeRoute(
                navigation =
                    HomeNavigation(
                        onOpenScan = { onTab(Tab.SCAN) },
                        onOpenThreats = { onTab(Tab.THREATS) },
                        onOpenWebShield = { onOpen(Overlay.WEB_SHIELD) },
                        onOpenSchedule = { onTab(Tab.SETTINGS) },
                        onOpenHistory = { onOpen(Overlay.HISTORY) }
                    ),
                modifier = modifier
            )

        Tab.SCAN -> ScanRoute(modifier = modifier, viewModel = scan)

        Tab.THREATS -> ThreatsRoute(onOpenHistory = { onOpen(Overlay.HISTORY) }, modifier = modifier)

        Tab.SETTINGS ->
            SettingsRoute(
                modifier = modifier,
                onOpenTroubleshooting = { onOpen(Overlay.TROUBLESHOOTING) },
                onOpenWebShield = { onOpen(Overlay.WEB_SHIELD) }
            )
    }
}
