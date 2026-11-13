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
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

@Composable
internal fun StatsCard(state: WebShieldUiState) {
    Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp)) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(stringResource(R.string.webshield_stats_title), style = MaterialTheme.typography.titleMedium)
            Row(
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
            ) {
                Stat(stringResource(R.string.webshield_stats_today), state.stats.today, "blockedToday")
                Stat(stringResource(R.string.webshield_stats_week), state.stats.last7Days, "blockedWeek")
                Stat(stringResource(R.string.webshield_stats_total), state.stats.total, "blockedTotal")
            }
            Text(
                stringResource(R.string.webshield_stats_split, state.stats.totalMalware, state.stats.totalPhishing),
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 8.dp)
            )
        }
    }
}

@Composable
internal fun Stat(label: String, value: Long, tag: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value.toString(), style = MaterialTheme.typography.headlineSmall, modifier = Modifier.testTag(tag))
        Text(label, style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
internal fun BlocklistRow(state: WebShieldUiState) {
    val updated = state.blocklistUpdatedAt
    ListItem(
        headlineContent = { Text(stringResource(R.string.webshield_list_title)) },
        supportingContent = {
            Text(
                if (state.blocklistSize == 0L && updated == null) {
                    stringResource(R.string.webshield_list_never)
                } else {
                    pluralStringResource(
                        R.plurals.webshield_list_count,
                        state.blocklistSize.toInt().coerceAtMost(Int.MAX_VALUE),
                        state.blocklistSize
                    ) +
                        (
                            updated?.let {
                                " · " +
                                    stringResource(
                                        R.string.webshield_list_updated,
                                        DateUtils.getRelativeTimeSpanString(it.toEpochMilli())
                                    )
                            }
                                ?: ""
                            )
                }
            )
        }
    )
}

@Composable
internal fun SwitchRow(title: String, summary: String, checked: Boolean, tag: String, onChange: (Boolean) -> Unit) {
    ListItem(
        headlineContent = { Text(title) },
        supportingContent = { Text(summary) },
        trailingContent = { Switch(checked = checked, onCheckedChange = onChange, modifier = Modifier.testTag(tag)) }
    )
}

@Composable
internal fun AllowListSection(domains: List<String>, onAllow: (String) -> Boolean, onRemove: (String) -> Unit) {
    var input by rememberSaveable { mutableStateOf("") }
    var invalid by remember { mutableStateOf(false) }
    ListItem(
        headlineContent = { Text(stringResource(R.string.webshield_allow_title)) },
        supportingContent = { Text(stringResource(R.string.webshield_allow_summary)) }
    )
    domains.forEach { domain ->
        Row(
            modifier = Modifier.fillMaxWidth().padding(start = 32.dp, end = 16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(domain, modifier = Modifier.weight(1f))
            TextButton(onClick = { onRemove(domain) }) { Text(stringResource(R.string.webshield_allow_remove)) }
        }
    }
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        OutlinedTextField(
            value = input,
            onValueChange = {
                input = it
                invalid = false
            },
            placeholder = { Text(stringResource(R.string.webshield_allow_hint)) },
            isError = invalid,
            supportingText = if (invalid) ({ Text(stringResource(R.string.webshield_allow_invalid)) }) else null,
            singleLine = true,
            modifier = Modifier.weight(1f).testTag("allowInput")
        )
        Spacer(Modifier.width(8.dp))
        OutlinedButton(onClick = {
            if (onAllow(input)) input = "" else invalid = true
        }, modifier = Modifier.testTag("allowAdd")) { Text(stringResource(R.string.webshield_allow_add)) }
    }
}

@Composable
internal fun OnboardingDialog(onContinue: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.webshield_onboarding_title)) },
        text = { Text(stringResource(R.string.webshield_onboarding_body)) },
        confirmButton = {
            TextButton(onClick = onContinue, modifier = Modifier.testTag("onboardingContinue")) {
                Text(stringResource(R.string.webshield_onboarding_continue))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.webshield_onboarding_cancel)) }
        }
    )
}
