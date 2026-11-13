package com.blackshield.feature.settings

import android.text.format.DateUtils
import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.blackshield.core.sync.SyncErrorKind
import java.text.NumberFormat
import java.time.Instant

@Composable
fun SettingsRoute(modifier: Modifier = Modifier, viewModel: SettingsViewModel = hiltViewModel()) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    SettingsScreen(
        state = state,
        onRealTimeProtectionChange = viewModel::setRealTimeProtectionEnabled,
        onWifiOnlyChange = viewModel::setWifiOnly,
        onSyncNow = viewModel::syncNow,
        modifier = modifier
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    state: SettingsUiState,
    onRealTimeProtectionChange: (Boolean) -> Unit,
    onWifiOnlyChange: (Boolean) -> Unit,
    onSyncNow: () -> Unit,
    modifier: Modifier = Modifier
) {
    Scaffold(
        modifier = modifier.fillMaxSize(),
        topBar = { TopAppBar(title = { Text(stringResource(R.string.settings_title)) }) }
    ) { innerPadding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(innerPadding).verticalScroll(rememberScrollState())
        ) {
            SectionHeader(R.string.settings_section_protection)
            SwitchRow(
                title = stringResource(R.string.settings_real_time_protection),
                checked = state.realTimeProtectionEnabled,
                onCheckedChange = onRealTimeProtectionChange
            )
            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
            SectionHeader(R.string.settings_section_signatures)
            SignatureDatabaseSection(state.signatures, onSyncNow)
            SwitchRow(
                title = stringResource(R.string.settings_wifi_only),
                summary = stringResource(R.string.settings_wifi_only_summary),
                checked = state.wifiOnly,
                onCheckedChange = onWifiOnlyChange
            )
        }
    }
}

@Composable
private fun SignatureDatabaseSection(status: SignatureDatabaseStatus, onSyncNow: () -> Unit) {
    val numbers = NumberFormat.getIntegerInstance()
    InfoRow(
        label = stringResource(R.string.settings_signature_version),
        value =
            if (status.version > 0) {
                numbers.format(status.version)
            } else {
                stringResource(R.string.settings_signature_version_none)
            },
        tag = "signatureVersion"
    )
    InfoRow(stringResource(R.string.settings_signature_count), numbers.format(status.count), "signatureCount")
    InfoRow(
        label = stringResource(R.string.settings_last_sync),
        value = status.lastSuccessAt?.let(::relativeTime) ?: stringResource(R.string.settings_last_sync_never),
        tag = "lastSync"
    )
    if (!status.syncing) {
        status.lastError?.let { SyncErrorMessage(it) }
    }
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Button(onClick = onSyncNow, enabled = !status.syncing, modifier = Modifier.testTag("syncNow")) {
            Text(stringResource(R.string.settings_sync_now))
        }
        if (status.syncing) {
            CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
            Text(stringResource(R.string.settings_syncing), style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun SyncErrorMessage(error: SyncErrorKind) {
    Column(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp).testTag("syncError")) {
        Text(
            text = stringResource(errorMessage(error)),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.error
        )
        Text(
            text =
                stringResource(
                    if (error.retryable) R.string.settings_sync_error_retrying else R.string.settings_sync_error_kept
                ),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@StringRes
private fun errorMessage(error: SyncErrorKind): Int = when (error) {
    SyncErrorKind.NETWORK -> R.string.settings_sync_error_network
    SyncErrorKind.INCOMPLETE_DOWNLOAD -> R.string.settings_sync_error_incomplete
    SyncErrorKind.SERVER -> R.string.settings_sync_error_server
    SyncErrorKind.RATE_LIMITED -> R.string.settings_sync_error_rate_limited
    SyncErrorKind.CORRUPT_DATA -> R.string.settings_sync_error_corrupt
    SyncErrorKind.STORAGE -> R.string.settings_sync_error_storage
    SyncErrorKind.UNAUTHORIZED -> R.string.settings_sync_error_unauthorized
    SyncErrorKind.CERTIFICATE -> R.string.settings_sync_error_certificate
    SyncErrorKind.UNKNOWN -> R.string.settings_sync_error_unknown
}

private fun relativeTime(instant: Instant): String = DateUtils
    .getRelativeTimeSpanString(instant.toEpochMilli(), System.currentTimeMillis(), DateUtils.MINUTE_IN_MILLIS)
    .toString()

@Composable
private fun SectionHeader(@StringRes title: Int) {
    Text(
        text = stringResource(title),
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 4.dp)
    )
}

@Composable
private fun InfoRow(label: String, value: String, tag: String) {
    ListItem(
        headlineContent = { Text(label) },
        trailingContent = { Text(value, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.testTag(tag)) }
    )
}

/** The whole row toggles, announced as a switch. */
@Composable
private fun SwitchRow(title: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit, summary: String? = null) {
    Row(
        modifier =
            Modifier
                .fillMaxWidth()
                .toggleable(value = checked, role = Role.Switch, onValueChange = onCheckedChange)
                .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            if (summary != null) {
                Text(
                    summary,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        Spacer(modifier = Modifier.width(16.dp))
        Switch(checked = checked, onCheckedChange = null)
    }
}

@Preview(showBackground = true)
@Composable
private fun SettingsScreenPreview() {
    MaterialTheme {
        SettingsScreen(
            state =
                SettingsUiState(
                    signatures =
                        SignatureDatabaseStatus(
                            version = 42,
                            count = 499_960,
                            lastSuccessAt = Instant.now().minusSeconds(600),
                            lastError = SyncErrorKind.NETWORK
                        )
                ),
            onRealTimeProtectionChange = {},
            onWifiOnlyChange = {},
            onSyncNow = {}
        )
    }
}
