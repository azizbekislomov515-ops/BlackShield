package com.blackshield.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.core.content.ContextCompat
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.blackshield.app.ui.theme.BlackShieldTheme
import com.blackshield.core.data.model.ScanResult
import com.blackshield.core.data.prefs.UserPreferencesRepository
import com.blackshield.feature.protection.FileResultCodec
import com.blackshield.feature.protection.ProtectionController
import com.blackshield.feature.protection.ProtectionIntents
import com.blackshield.feature.protection.ProtectionStateStore
import com.blackshield.feature.protection.troubleshooting.TroubleshootingRoute
import com.blackshield.feature.scan.ScanResultDetailsSheet
import com.blackshield.feature.scan.ScanRoute
import com.blackshield.feature.scan.ScanViewModel
import com.blackshield.feature.settings.SettingsRoute
import com.blackshield.feature.webshield.WebShieldController
import com.blackshield.feature.webshield.WebShieldNotifications
import com.blackshield.feature.webshield.WebShieldRoute
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

@AndroidEntryPoint
class MainActivity : ComponentActivity() {
    @Inject lateinit var preferences: UserPreferencesRepository

    @Inject lateinit var protection: ProtectionController

    @Inject lateinit var protectionState: ProtectionStateStore

    @Inject lateinit var webShield: WebShieldController

    /** What a notification asked to show: a package's result or a downloaded file's result. */
    private val deepLink = MutableStateFlow<DeepLink?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
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
            BlackShieldTheme {
                BlackShieldApp(
                    deepLink = deepLink,
                    shouldPromptForNotifications = ::shouldPromptForNotifications,
                    onNotificationPromptShown = {
                        lifecycleScope.launch { protectionState.setNotificationPromptShown() }
                    }
                )
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
        intent ?: return
        val link =
            when {
                intent.getBooleanExtra(WebShieldNotifications.EXTRA_SHOW_WEB_SHIELD, false) -> DeepLink.WebShield

                else ->
                    FileResultCodec.decode(
                        intent.getStringExtra(ProtectionIntents.EXTRA_FILE_RESULT)
                    )?.let(DeepLink::File)
                        ?: intent.getStringExtra(ProtectionIntents.EXTRA_SHOW_PACKAGE)?.let(DeepLink::Package)
            }
        link?.let { deepLink.value = it }
    }

    /** Once, on Android 13+, when protection is on but warnings could not be shown. */
    private suspend fun shouldPromptForNotifications(): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED &&
            preferences.realTimeProtectionEnabled.first() &&
            !protectionState.notificationPromptShown()
}

sealed interface DeepLink {
    data class Package(val packageName: String) : DeepLink

    data class File(val result: ScanResult) : DeepLink

    data object WebShield : DeepLink
}

private enum class Destination(@StringRes val label: Int, @DrawableRes val icon: Int) {
    SCAN(R.string.nav_scan, R.drawable.ic_nav_scan),
    WEB_SHIELD(R.string.nav_web_shield, R.drawable.ic_nav_webshield),
    SETTINGS(R.string.nav_settings, R.drawable.ic_nav_settings)
}

@Composable
private fun BlackShieldApp(
    deepLink: MutableStateFlow<DeepLink?>,
    shouldPromptForNotifications: suspend () -> Boolean,
    onNotificationPromptShown: () -> Unit
) {
    var destination by rememberSaveable { mutableStateOf(Destination.SCAN) }
    var troubleshooting by rememberSaveable { mutableStateOf(false) }
    var shownFile by remember { mutableStateOf<ScanResult?>(null) }
    var notificationPrompt by rememberSaveable { mutableStateOf(false) }
    val scanViewModel: ScanViewModel = hiltViewModel()
    val scope = rememberCoroutineScope()
    val requestNotifications =
        rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { onNotificationPromptShown() }

    LaunchedEffect(Unit) {
        if (shouldPromptForNotifications()) notificationPrompt = true
        deepLink.collect { link ->
            when (link) {
                is DeepLink.Package -> {
                    troubleshooting = false
                    destination = Destination.SCAN
                    scanViewModel.showDetails(link.packageName)
                }

                is DeepLink.File -> shownFile = link.result

                DeepLink.WebShield -> {
                    troubleshooting = false
                    destination = Destination.WEB_SHIELD
                }

                null -> Unit
            }
            deepLink.value = null
        }
    }

    if (troubleshooting) {
        TroubleshootingRoute(onBack = { troubleshooting = false })
        return
    }
    Scaffold(
        bottomBar = {
            NavigationBar {
                Destination.entries.forEach { item ->
                    NavigationBarItem(
                        selected = item == destination,
                        onClick = { destination = item },
                        icon = { Icon(painterResource(item.icon), contentDescription = null) },
                        label = { Text(stringResource(item.label)) }
                    )
                }
            }
        }
    ) { innerPadding ->
        // Each screen has its own Scaffold; consuming the insets here stops it adding them twice.
        val content = Modifier.fillMaxSize().padding(innerPadding).consumeWindowInsets(innerPadding)
        when (destination) {
            Destination.SCAN -> ScanRoute(modifier = content, viewModel = scanViewModel)

            Destination.WEB_SHIELD -> WebShieldRoute(modifier = content)

            Destination.SETTINGS -> SettingsRoute(modifier = content, onOpenTroubleshooting = {
                troubleshooting = true
            })
        }
    }

    shownFile?.let { file ->
        ScanResultDetailsSheet(result = file, trusted = false, onTrustedChange = {
        }, onDismiss = { shownFile = null }, showTrust = false)
    }

    if (notificationPrompt) {
        AlertDialog(
            onDismissRequest = {
                notificationPrompt = false
                onNotificationPromptShown()
            },
            title = { Text(stringResource(R.string.notification_prompt_title)) },
            text = { Text(stringResource(R.string.notification_prompt_body)) },
            confirmButton = {
                TextButton(onClick = {
                    notificationPrompt = false
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        scope.launch { requestNotifications.launch(Manifest.permission.POST_NOTIFICATIONS) }
                    }
                }) { Text(stringResource(R.string.notification_prompt_allow)) }
            },
            dismissButton = {
                TextButton(onClick = {
                    notificationPrompt = false
                    onNotificationPromptShown()
                }) { Text(stringResource(R.string.notification_prompt_later)) }
            }
        )
    }
}
