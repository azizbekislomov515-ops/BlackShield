package com.blackshield.feature.protection.troubleshooting

import android.content.ActivityNotFoundException
import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.blackshield.feature.protection.ProtectionController
import com.blackshield.feature.protection.R
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import timber.log.Timber

data class TroubleshootingState(
    val loaded: Boolean = false,
    val oem: Oem = Oem.OTHER,
    val issues: List<Issue> = emptyList()
)

@HiltViewModel
class TroubleshootingViewModel
@Inject
constructor(
    private val reader: DeviceHealthReader,
    private val controller: ProtectionController
) : ViewModel() {
    private val state = MutableStateFlow(TroubleshootingState())
    val uiState: StateFlow<TroubleshootingState> = state.asStateFlow()

    /** Re-checked every time the screen resumes, e.g. after the user changed a system setting. */
    fun refresh() {
        viewModelScope.launch {
            val health = reader.read()
            state.value = TroubleshootingState(true, health.oem, TroubleshootingChecks.evaluate(health))
        }
    }

    fun fix(issue: Issue, oem: Oem): android.content.Intent? = when (issue.fix) {
        FixAction.ENABLE_PROTECTION -> {
            viewModelScope.launch {
                controller.setEnabled(true)
                refresh()
            }
            null
        }

        FixAction.RESTART_PROTECTION -> {
            controller.start()
            refresh()
            null
        }

        else -> reader.intentFor(issue.fix, oem)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TroubleshootingRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: TroubleshootingViewModel = hiltViewModel()
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { viewModel.refresh() }
    Scaffold(
        modifier = modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.troubleshooting_title)) },
                navigationIcon = {
                    TextButton(onClick = onBack) { Text(stringResource(R.string.troubleshooting_back)) }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(stringResource(R.string.troubleshooting_intro), style = MaterialTheme.typography.bodyMedium)
            if (state.loaded && state.issues.isEmpty()) {
                Text(
                    stringResource(R.string.troubleshooting_all_good),
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.testTag("troubleshootingAllGood")
                )
            }
            state.issues.forEach { issue ->
                IssueCard(issue, state.oem) {
                    viewModel.fix(issue, state.oem)?.let { intent ->
                        try {
                            context.startActivity(intent)
                        } catch (e: ActivityNotFoundException) {
                            Timber.w(e, "No settings screen for %s", issue.fix)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun IssueCard(issue: Issue, oem: Oem, onFix: () -> Unit) {
    val colors =
        when (issue.severity) {
            Severity.CRITICAL -> CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)
            Severity.WARNING -> CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer)
            Severity.INFO -> CardDefaults.cardColors()
        }
    Card(colors = colors, modifier = Modifier.fillMaxWidth().testTag("issue_${issue.kind}")) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(titleOf(issue.kind)), style = MaterialTheme.typography.titleSmall)
            Text(bodyOf(issue.kind, oem), style = MaterialTheme.typography.bodyMedium)
            OutlinedButton(onClick = onFix) { Text(stringResource(fixLabel(issue.fix))) }
        }
    }
}

@StringRes
private fun titleOf(kind: IssueKind): Int = when (kind) {
    IssueKind.PROTECTION_OFF -> R.string.issue_protection_off_title
    IssueKind.SERVICE_NOT_RUNNING -> R.string.issue_not_running_title
    IssueKind.NOTIFICATIONS_BLOCKED -> R.string.issue_notifications_title
    IssueKind.THREAT_ALERTS_BLOCKED -> R.string.issue_threat_channel_title
    IssueKind.BACKGROUND_RESTRICTED -> R.string.issue_background_title
    IssueKind.BATTERY_OPTIMIZED -> R.string.issue_battery_title
    IssueKind.RARELY_USED_BUCKET -> R.string.issue_bucket_title
    IssueKind.DOWNLOADS_ACCESS_MISSING -> R.string.issue_downloads_title
    IssueKind.OEM_TASK_KILLER -> R.string.issue_oem_title
}

@Composable
private fun bodyOf(kind: IssueKind, oem: Oem): String = when (kind) {
    IssueKind.PROTECTION_OFF -> stringResource(R.string.issue_protection_off_body)
    IssueKind.SERVICE_NOT_RUNNING -> stringResource(R.string.issue_not_running_body)
    IssueKind.NOTIFICATIONS_BLOCKED -> stringResource(R.string.issue_notifications_body)
    IssueKind.THREAT_ALERTS_BLOCKED -> stringResource(R.string.issue_threat_channel_body)
    IssueKind.BACKGROUND_RESTRICTED -> stringResource(R.string.issue_background_body)
    IssueKind.BATTERY_OPTIMIZED -> stringResource(R.string.issue_battery_body)
    IssueKind.RARELY_USED_BUCKET -> stringResource(R.string.issue_bucket_body)
    IssueKind.DOWNLOADS_ACCESS_MISSING -> stringResource(R.string.issue_downloads_body)
    IssueKind.OEM_TASK_KILLER -> stringResource(oemGuidance(oem))
}

@StringRes
private fun oemGuidance(oem: Oem): Int = when (oem) {
    Oem.XIAOMI -> R.string.oem_xiaomi
    Oem.HUAWEI -> R.string.oem_huawei
    Oem.SAMSUNG -> R.string.oem_samsung
    Oem.ONEPLUS -> R.string.oem_oneplus
    Oem.OPPO -> R.string.oem_oppo
    Oem.VIVO -> R.string.oem_vivo
    Oem.OTHER -> R.string.issue_battery_body
}

@StringRes
private fun fixLabel(fix: FixAction): Int = when (fix) {
    FixAction.ENABLE_PROTECTION -> R.string.fix_enable
    FixAction.RESTART_PROTECTION -> R.string.fix_restart
    FixAction.NOTIFICATION_SETTINGS, FixAction.THREAT_CHANNEL_SETTINGS -> R.string.fix_notifications
    FixAction.BATTERY_OPTIMIZATION_SETTINGS -> R.string.fix_battery
    FixAction.APP_DETAILS -> R.string.fix_app_settings
    FixAction.ALL_FILES_ACCESS -> R.string.fix_all_files
    FixAction.OEM_SETTINGS -> R.string.fix_oem
}
