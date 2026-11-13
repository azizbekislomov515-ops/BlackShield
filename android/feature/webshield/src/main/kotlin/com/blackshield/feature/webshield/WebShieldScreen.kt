package com.blackshield.feature.webshield

import android.Manifest
import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import android.text.format.DateUtils
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

@Composable
fun WebShieldRoute(modifier: Modifier = Modifier, viewModel: WebShieldViewModel = hiltViewModel()) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    var onboarding by rememberSaveable { mutableStateOf(false) }
    val requestNotifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }
    val enable = {
        viewModel.enable()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !notificationsGranted(context)) {
            requestNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
    val requestVpn =
        rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) enable()
        }
    WebShieldScreen(
        state = state,
        modifier = modifier,
        onEnabledChange = { on ->
            when {
                !on -> viewModel.disable()

                viewModel.consentIntent() != null -> onboarding = true

                // explain before the system dialog
                else -> enable()
            }
        },
        onNotifyChange = { viewModel.setNotifyBlocked(it) },
        onActivityLogChange = { viewModel.setActivityLog(it) },
        onClearActivity = { viewModel.clearActivity() },
        onAllow = viewModel::allow,
        onRemoveAllowed = { viewModel.removeAllowed(it) },
        onOpenNetworkSettings = { open(context, Intent(Settings.ACTION_WIRELESS_SETTINGS)) }
    )
    if (onboarding) {
        OnboardingDialog(
            onContinue = {
                onboarding = false
                viewModel.consentIntent()?.let(requestVpn::launch) ?: enable()
            },
            onDismiss = { onboarding = false }
        )
    }
}

@Composable
fun WebShieldScreen(
    state: WebShieldUiState,
    onEnabledChange: (Boolean) -> Unit,
    onNotifyChange: (Boolean) -> Unit,
    onActivityLogChange: (Boolean) -> Unit,
    onClearActivity: () -> Unit,
    onAllow: (String) -> Boolean,
    onRemoveAllowed: (String) -> Unit,
    onOpenNetworkSettings: () -> Unit,
    modifier: Modifier = Modifier
) {
    LazyColumn(modifier = modifier.fillMaxSize().testTag("webShield")) {
        item { StatusCard(state, onEnabledChange, onOpenNetworkSettings) }
        item { StatsCard(state) }
        item { BlocklistRow(state) }
        item { HorizontalDivider() }
        item {
            SwitchRow(
                stringResource(R.string.webshield_notify),
                stringResource(R.string.webshield_notify_summary),
                state.notifyBlocked,
                "notifyBlocked",
                onNotifyChange
            )
        }
        item { AllowListSection(state.allowList, onAllow, onRemoveAllowed) }
        item { HorizontalDivider() }
        item {
            SwitchRow(
                stringResource(R.string.webshield_activity),
                stringResource(R.string.webshield_activity_summary),
                state.activityLog,
                "activityLog",
                onActivityLogChange
            )
        }
        if (state.activityLog) {
            if (state.activity.isEmpty()) {
                item {
                    Text(
                        stringResource(R.string.webshield_activity_empty),
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)
                    )
                }
            }
            items(state.activity, key = { it.id }) { entry ->
                ListItem(
                    headlineContent = { Text(entry.domain) },
                    supportingContent = {
                        Text(
                            "${entry.category.name.lowercase()} · ${DateUtils.getRelativeTimeSpanString(
                                entry.blockedAt
                            )}"
                        )
                    }
                )
            }
            item {
                TextButton(onClick = onClearActivity, modifier = Modifier.padding(horizontal = 8.dp)) {
                    Text(stringResource(R.string.webshield_activity_clear))
                }
            }
        }
        item {
            Text(
                stringResource(R.string.webshield_note_browsers),
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(16.dp)
            )
        }
    }
}

@Composable
private fun StatusCard(state: WebShieldUiState, onEnabledChange: (Boolean) -> Unit, onOpenNetworkSettings: () -> Unit) {
    val status = state.status
    val on = status is WebShieldStatus.On || status == WebShieldStatus.Starting
    Card(
        modifier = Modifier.fillMaxWidth().padding(16.dp),
        colors =
            CardDefaults.cardColors(
                containerColor =
                    if (on) {
                        MaterialTheme.colorScheme.primaryContainer
                    } else {
                        MaterialTheme.colorScheme.surfaceVariant
                    }
            )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.webshield_title), style = MaterialTheme.typography.titleLarge)
                    Text(
                        stringResource(statusText(status)),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.testTag("webShieldStatus")
                    )
                }
                Switch(checked = on, onCheckedChange = onEnabledChange, modifier = Modifier.testTag("webShieldSwitch"))
            }
            Spacer(Modifier.padding(4.dp))
            Text(stringResource(R.string.webshield_summary), style = MaterialTheme.typography.bodySmall)
            StatusWarnings(state, onEnabledChange, onOpenNetworkSettings)
        }
    }
}

@Composable
private fun StatusWarnings(
    state: WebShieldUiState,
    onEnabledChange: (Boolean) -> Unit,
    onOpenNetworkSettings: () -> Unit
) {
    when (val status = state.status) {
        is WebShieldStatus.On -> {
            status.privateDnsBypass?.let { server ->
                Warning(
                    stringResource(R.string.webshield_warning_private_dns, server),
                    stringResource(R.string.webshield_open_settings),
                    onOpenNetworkSettings
                )
            }
            if (status.upstreamServers == 0) Warning(stringResource(R.string.webshield_warning_no_network))
            if (status.alwaysOn) Warning(stringResource(R.string.webshield_always_on))
        }

        is WebShieldStatus.Stopped -> if (status.reason == StopReason.REVOKED && !state.enabled) {
            Warning(
                stringResource(R.string.webshield_status_revoked),
                stringResource(R.string.webshield_turn_on_again)
            ) {
                onEnabledChange(true)
            }
        }

        else -> Unit
    }
}

@Composable
private fun Warning(text: String, action: String? = null, onAction: () -> Unit = {}) {
    Column(modifier = Modifier.padding(top = 12.dp)) {
        Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
        if (action != null) TextButton(onClick = onAction) { Text(action) }
    }
}

private fun statusText(status: WebShieldStatus): Int = when (status) {
    WebShieldStatus.Off -> R.string.webshield_status_off

    WebShieldStatus.Starting -> R.string.webshield_status_starting

    is WebShieldStatus.On -> R.string.webshield_status_on

    is WebShieldStatus.Stopped -> when (status.reason) {
        StopReason.NO_PERMISSION -> R.string.webshield_status_no_permission
        StopReason.REVOKED -> R.string.webshield_status_revoked
        StopReason.ESTABLISH_FAILED -> R.string.webshield_status_failed
    }
}

private fun notificationsGranted(context: Context): Boolean = Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
    ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) ==
    android.content.pm.PackageManager.PERMISSION_GRANTED

private fun open(context: Context, intent: Intent) {
    try {
        context.startActivity(intent)
    } catch (_: ActivityNotFoundException) {
        context.startActivity(Intent(Settings.ACTION_SETTINGS))
    }
}
