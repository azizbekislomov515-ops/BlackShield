package com.blackshield.feature.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

@Composable
fun SettingsRoute(modifier: Modifier = Modifier, viewModel: SettingsViewModel = hiltViewModel()) {
    val realTimeProtection by viewModel.realTimeProtectionEnabled.collectAsStateWithLifecycle()
    SettingsScreen(
        realTimeProtectionEnabled = realTimeProtection,
        onRealTimeProtectionChange = viewModel::setRealTimeProtectionEnabled,
        modifier = modifier
    )
}

@Composable
fun SettingsScreen(
    realTimeProtectionEnabled: Boolean,
    onRealTimeProtectionChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier.fillMaxWidth().padding(16.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = stringResource(R.string.settings_real_time_protection),
            style = MaterialTheme.typography.bodyLarge
        )
        Switch(checked = realTimeProtectionEnabled, onCheckedChange = onRealTimeProtectionChange)
    }
}

@Preview(showBackground = true)
@Composable
private fun SettingsScreenPreview() {
    MaterialTheme { SettingsScreen(realTimeProtectionEnabled = true, onRealTimeProtectionChange = {}) }
}
