package com.blackshield.feature.threats

import android.content.Intent
import android.text.format.Formatter
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.blackshield.core.data.model.FileThreat
import com.blackshield.core.data.model.ScanResult
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.designsystem.R as DsR
import com.blackshield.core.designsystem.component.BsCard
import com.blackshield.core.designsystem.component.BsTopBar
import com.blackshield.core.designsystem.component.EmptyState
import com.blackshield.core.designsystem.component.IconTile
import com.blackshield.core.designsystem.component.ListRow
import com.blackshield.core.designsystem.component.SectionHeader
import com.blackshield.core.designsystem.component.StatusChip
import com.blackshield.core.designsystem.theme.BsTheme
import com.blackshield.core.designsystem.theme.LabelMono
import com.blackshield.feature.scan.ScanResultDetailsSheet
import com.blackshield.feature.scan.VerdictChip

@Composable
fun ThreatsRoute(
    onOpenHistory: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ThreatsViewModel = hiltViewModel()
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val resources = LocalResources.current
    val snackbar = remember { SnackbarHostState() }
    var uninstalling by rememberSaveable { mutableStateOf<String?>(null) }
    var restoring by rememberSaveable { mutableStateOf<Long?>(null) }
    var confirmDelete by rememberSaveable { mutableStateOf<Long?>(null) }
    val uninstall =
        rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            uninstalling?.let(viewModel::onUninstallFinished)
            uninstalling = null
        }
    val restore =
        rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument(APK_MIME)) { uri ->
            val id = restoring
            if (uri != null && id != null) viewModel.restore(id, uri)
            restoring = null
        }
    LaunchedEffect(Unit) { viewModel.events.collect { snackbar.showSnackbar(resources.getString(messageText(it))) } }

    ThreatsScreen(
        state = state,
        actions =
            ThreatActions(
                onAppDetails = { viewModel.showApp(it) },
                onUninstall = { pkg ->
                    uninstalling = pkg
                    uninstall.launch(Intent(Intent.ACTION_DELETE, "package:$pkg".toUri()))
                },
                onQuarantine = viewModel::quarantine,
                onIgnore = viewModel::ignore,
                onRestore = { threat ->
                    restoring = threat.id
                    restore.launch(threat.displayName)
                },
                onDelete = { confirmDelete = it.id },
                onOpenHistory = onOpenHistory
            ),
        snackbar = snackbar,
        modifier = modifier
    )
    state.selectedApp?.let { app ->
        ScanResultDetailsSheet(
            result = app,
            trusted = false,
            onTrustedChange = { trusted -> if (trusted) viewModel.trust(app.packageName) },
            onDismiss = { viewModel.showApp(null) }
        )
    }
    confirmDelete?.let { id ->
        AlertDialog(
            onDismissRequest = { confirmDelete = null },
            title = { Text(stringResource(R.string.threats_delete_title)) },
            text = { Text(stringResource(R.string.threats_delete_body)) },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.deleteForever(id)
                    confirmDelete = null
                }, modifier = Modifier.testTag("confirmDelete")) {
                    Text(stringResource(R.string.threats_delete_confirm))
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmDelete = null }) { Text(stringResource(R.string.threats_cancel)) }
            }
        )
    }
}

data class ThreatActions(
    val onAppDetails: (String) -> Unit,
    val onUninstall: (String) -> Unit,
    val onQuarantine: (Long) -> Unit,
    val onIgnore: (Long) -> Unit,
    val onRestore: (FileThreat) -> Unit,
    val onDelete: (FileThreat) -> Unit,
    val onOpenHistory: () -> Unit
)

@Composable
fun ThreatsScreen(
    state: ThreatsUiState,
    actions: ThreatActions,
    modifier: Modifier = Modifier,
    snackbar: SnackbarHostState = remember { SnackbarHostState() }
) {
    Scaffold(
        modifier = modifier.fillMaxSize(),
        topBar = {
            BsTopBar(stringResource(R.string.threats_title), actions = {
                TextButton(onClick = actions.onOpenHistory, modifier = Modifier.testTag("openHistory")) {
                    Text(stringResource(R.string.threats_history))
                }
            })
        },
        snackbarHost = { SnackbarHost(snackbar) }
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().testTag("threats"),
            contentPadding = PaddingValues(
                start = 16.dp,
                end = 16.dp,
                top = padding.calculateTopPadding(),
                bottom = 24.dp
            ),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item(key = "summary") { Summary(state) }
            if (state.apps.isNotEmpty()) {
                item(key = "appsHeader") {
                    SectionHeader(stringResource(R.string.threats_apps))
                }
            }
            items(state.apps, key = { "app:${it.packageName}" }) { app -> AppThreatCard(app, actions) }
            if (state.files.isNotEmpty()) {
                item(key = "filesHeader") {
                    SectionHeader(stringResource(R.string.threats_files))
                }
            }
            items(state.files, key = { "file:${it.id}" }) { file -> FileThreatCard(file, actions) }
            item(key = "vaultHeader") {
                SectionHeader(stringResource(R.string.threats_vault)) {
                    StatusChip(stringResource(R.string.threats_vault_encrypted), BsTheme.status.info)
                }
            }
            if (state.vault.isEmpty()) {
                item(key = "vaultEmpty") {
                    EmptyState(
                        DsR.drawable.bs_ic_lock,
                        stringResource(R.string.threats_vault_empty),
                        body = stringResource(R.string.threats_vault_empty_body)
                    )
                }
            }
            items(state.vault, key = { "vault:${it.id}" }) { file -> VaultRow(file, actions) }
        }
    }
}

@Composable
private fun Summary(state: ThreatsUiState) {
    val count = state.openThreats
    val color = if (count == 0) BsTheme.status.safe else BsTheme.status.danger
    BsCard {
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            IconTile(
                if (count ==
                    0
                ) {
                    DsR.drawable.bs_ic_shield_check
                } else {
                    DsR.drawable.bs_ic_report
                },
                color,
                size = 48.dp
            )
            Column(Modifier.weight(1f)) {
                Text(
                    if (count ==
                        0
                    ) {
                        stringResource(R.string.threats_none)
                    } else {
                        pluralStringResource(R.plurals.threats_count, count, count)
                    },
                    style = MaterialTheme.typography.titleLarge,
                    modifier = Modifier.testTag("threatsSummary")
                )
                Text(
                    stringResource(if (count == 0) R.string.threats_none_body else R.string.threats_count_body),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

/** A card with a severity stripe on its leading edge. */
@Composable
private fun ThreatCard(verdict: Verdict, content: @Composable () -> Unit) {
    val stripe: Color = if (verdict == Verdict.MALICIOUS) BsTheme.status.danger else BsTheme.status.caution
    BsCard {
        Row(Modifier.height(IntrinsicSize.Min)) {
            Box(Modifier.width(4.dp).fillMaxHeight().background(stripe, MaterialTheme.shapes.extraSmall))
            Column(Modifier.padding(start = 12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) { content() }
        }
    }
}

@Composable
private fun AppThreatCard(app: ScanResult, actions: ThreatActions) {
    ThreatCard(app.verdict) {
        VerdictChip(app.verdict)
        Text(app.appLabel, style = MaterialTheme.typography.titleMedium)
        Text(app.packageName, style = LabelMono, color = MaterialTheme.colorScheme.onSurfaceVariant)
        TopReason(app.reasons.filter { it.points > 0 }.maxByOrNull { it.points }?.detail)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            DangerButton(stringResource(R.string.threats_uninstall), Modifier.weight(1f).testTag("uninstall")) {
                actions.onUninstall(app.packageName)
            }
            OutlinedButton(onClick = {
                actions.onAppDetails(app.packageName)
            }, modifier = Modifier.weight(1f).heightIn(min = 48.dp)) {
                Text(stringResource(R.string.threats_details))
            }
        }
    }
}

@Composable
private fun FileThreatCard(file: FileThreat, actions: ThreatActions) {
    ThreatCard(file.verdict) {
        VerdictChip(file.verdict)
        Text(file.appLabel ?: file.displayName, style = MaterialTheme.typography.titleMedium)
        Text(fileMeta(file), style = LabelMono, color = MaterialTheme.colorScheme.onSurfaceVariant)
        TopReason(file.reasons.filter { it.points > 0 }.maxByOrNull { it.points }?.detail)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            DangerButton(stringResource(R.string.threats_quarantine), Modifier.weight(1f).testTag("quarantine")) {
                actions.onQuarantine(file.id)
            }
            OutlinedButton(onClick = {
                actions.onIgnore(file.id)
            }, modifier = Modifier.weight(1f).heightIn(min = 48.dp)) {
                Text(stringResource(R.string.threats_ignore))
            }
        }
    }
}

@Composable
private fun TopReason(reason: String?) {
    if (!reason.isNullOrBlank()) Text(reason, style = MaterialTheme.typography.bodyMedium)
}

@Composable
internal fun DangerButton(text: String, modifier: Modifier, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        modifier = modifier.heightIn(min = 48.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = MaterialTheme.colorScheme.errorContainer,
            contentColor = MaterialTheme.colorScheme.onErrorContainer
        )
    ) { Text(text) }
}

private fun messageText(message: ThreatMessage): Int = when (message) {
    ThreatMessage.QUARANTINED -> R.string.message_quarantined
    ThreatMessage.ORIGINAL_KEPT -> R.string.message_original_kept
    ThreatMessage.QUARANTINE_FAILED -> R.string.message_quarantine_failed
    ThreatMessage.RESTORED -> R.string.message_restored
    ThreatMessage.RESTORE_FAILED -> R.string.message_restore_failed
    ThreatMessage.DELETED -> R.string.message_deleted
    ThreatMessage.UNINSTALLED -> R.string.message_uninstalled
    ThreatMessage.TRUSTED -> R.string.message_trusted
}

private const val APK_MIME = "application/vnd.android.package-archive"
