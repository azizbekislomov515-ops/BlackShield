package com.blackshield.feature.scan

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.blackshield.core.data.model.ScanResult
import com.blackshield.core.data.model.Verdict

@Composable
fun ScanRoute(modifier: Modifier = Modifier, viewModel: ScanViewModel = hiltViewModel()) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    ScanScreen(
        state = state,
        onScanNow = viewModel::startScan,
        onPause = viewModel::pause,
        onResume = viewModel::resume,
        onCancel = viewModel::cancel,
        onResultClick = viewModel::showDetails,
        modifier = modifier
    )
    state.selected?.let { selected ->
        ScanResultDetailsSheet(
            result = selected,
            trusted = selected.packageName in state.trustedPackages,
            onTrustedChange = { viewModel.setTrusted(selected.packageName, it) },
            onDismiss = viewModel::dismissDetails
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanScreen(
    state: ScanUiState,
    onScanNow: () -> Unit,
    onPause: () -> Unit,
    onResume: () -> Unit,
    onCancel: () -> Unit,
    onResultClick: (packageName: String) -> Unit,
    modifier: Modifier = Modifier
) {
    Scaffold(
        modifier = modifier.fillMaxSize(),
        topBar = { TopAppBar(title = { Text(stringResource(R.string.scan_title)) }) }
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().testTag("scanResults"),
            contentPadding = innerPadding
        ) {
            item(key = "status") {
                ScanStatusCard(
                    status = state.status,
                    onScanNow = onScanNow,
                    onPause = onPause,
                    onResume = onResume,
                    onCancel = onCancel,
                    modifier = Modifier.padding(16.dp)
                )
            }
            if (state.results.isEmpty() && state.status == ScanStatus.Idle) {
                item(key = "empty") {
                    Text(
                        text = stringResource(R.string.scan_no_results),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(horizontal = 16.dp)
                    )
                }
            }
            items(state.results, key = { it.packageName }) { result ->
                ScanResultRow(result = result, onClick = { onResultClick(result.packageName) })
                HorizontalDivider()
            }
        }
    }
}

@Composable
private fun ScanStatusCard(
    status: ScanStatus,
    onScanNow: () -> Unit,
    onPause: () -> Unit,
    onResume: () -> Unit,
    onCancel: () -> Unit,
    modifier: Modifier = Modifier
) {
    Card(modifier = modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            when (status) {
                ScanStatus.Idle -> {
                    Text(stringResource(R.string.scan_idle_title), style = MaterialTheme.typography.titleMedium)
                    Text(stringResource(R.string.scan_idle_body), style = MaterialTheme.typography.bodyMedium)
                    Button(onClick = onScanNow, modifier = Modifier.testTag("scanNow")) {
                        Text(stringResource(R.string.scan_now))
                    }
                }

                is ScanStatus.Running -> RunningStatus(status, onPause, onResume, onCancel)

                is ScanStatus.Finished -> {
                    Text(
                        pluralStringResource(
                            R.plurals.scan_finished,
                            status.total,
                            status.total,
                            status.durationMillis / MILLIS_PER_SECOND
                        ),
                        style = MaterialTheme.typography.titleMedium
                    )
                    Text(
                        stringResource(R.string.scan_finished_summary, status.malicious, status.suspicious),
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Button(onClick = onScanNow, modifier = Modifier.testTag("scanNow")) {
                        Text(stringResource(R.string.scan_again))
                    }
                }
            }
        }
    }
}

@Composable
private fun RunningStatus(status: ScanStatus.Running, onPause: () -> Unit, onResume: () -> Unit, onCancel: () -> Unit) {
    val title =
        if (status.paused) {
            stringResource(R.string.scan_paused, status.scanned, status.total)
        } else {
            stringResource(R.string.scan_progress, status.scanned, status.total)
        }
    Text(title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.testTag("scanProgress"))
    LinearProgressIndicator(
        progress = { if (status.total == 0) 0f else status.scanned.toFloat() / status.total },
        modifier = Modifier.fillMaxWidth()
    )
    status.currentApp?.let {
        Text(it, style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        if (status.paused) {
            Button(onClick = onResume) { Text(stringResource(R.string.scan_resume)) }
        } else {
            OutlinedButton(onClick = onPause) { Text(stringResource(R.string.scan_pause)) }
        }
        OutlinedButton(onClick = onCancel) { Text(stringResource(R.string.scan_cancel)) }
    }
}

@Composable
private fun ScanResultRow(result: ScanResult, onClick: () -> Unit) {
    ListItem(
        modifier = Modifier.clickable(onClick = onClick),
        headlineContent = { Text(result.appLabel, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        supportingContent = {
            Text(result.packageName, maxLines = 1, overflow = TextOverflow.Ellipsis)
        },
        trailingContent = { VerdictChip(result.verdict) }
    )
}

@Preview(showBackground = true)
@Composable
private fun ScanScreenPreview() {
    MaterialTheme {
        ScanScreen(
            state =
                ScanUiState(
                    results = PreviewData.results,
                    status = ScanStatus.Running(scanned = 37, total = 150, currentApp = "Chrome", paused = false)
                ),
            onScanNow = {},
            onPause = {},
            onResume = {},
            onCancel = {},
            onResultClick = {}
        )
    }
}

internal object PreviewData {
    val results =
        listOf(
            preview("com.example.eicar", "EICAR test app", Verdict.MALICIOUS, 100),
            preview("com.example.flashlight", "Free Flashlight", Verdict.SUSPICIOUS, 60),
            preview("com.android.chrome", "Chrome", Verdict.CLEAN, 0)
        )

    private fun preview(packageName: String, label: String, verdict: Verdict, score: Int) = ScanResult(
        packageName = packageName,
        appLabel = label,
        versionCode = 1,
        apkSha256 = PREVIEW_SHA256,
        verdict = verdict,
        riskScore = score,
        reasons = emptyList(),
        scannedAt = 0
    )
}

private const val MILLIS_PER_SECOND = 1000.0
private const val PREVIEW_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
