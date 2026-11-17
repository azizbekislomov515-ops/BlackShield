package com.blackshield.feature.scan

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.blackshield.core.data.model.ScanResult
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.designsystem.R as DsR
import com.blackshield.core.designsystem.component.BsCard
import com.blackshield.core.designsystem.component.BsTopBar
import com.blackshield.core.designsystem.component.EmptyState
import com.blackshield.core.designsystem.component.ListRow
import com.blackshield.core.designsystem.component.PrimaryActionButton
import com.blackshield.core.designsystem.component.SectionHeader
import com.blackshield.core.designsystem.component.StatTile
import com.blackshield.core.designsystem.theme.BsTheme
import com.blackshield.core.designsystem.theme.LabelMono

@Composable
fun ScanRoute(modifier: Modifier = Modifier, viewModel: ScanViewModel = hiltViewModel()) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val pickFile =
        rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            uri?.let(viewModel::scanFile)
        }
    ScanScreen(
        state = state,
        onScanNow = viewModel::startScan,
        onPause = viewModel::pause,
        onResume = viewModel::resume,
        onCancel = viewModel::cancel,
        onScanFile = { pickFile.launch(arrayOf(APK_MIME, "application/octet-stream", "*/*")) },
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
    state.fileScan?.let { file ->
        FileScanSheet(file, onQuarantine = viewModel::quarantineScannedFile, onDismiss = viewModel::dismissFileScan)
    }
}

@Composable
fun ScanScreen(
    state: ScanUiState,
    onScanNow: () -> Unit,
    onPause: () -> Unit,
    onResume: () -> Unit,
    onCancel: () -> Unit,
    onScanFile: () -> Unit,
    onResultClick: (packageName: String) -> Unit,
    modifier: Modifier = Modifier
) {
    Scaffold(modifier = modifier.fillMaxSize(), topBar = {
        BsTopBar(stringResource(R.string.scan_title))
    }) { innerPadding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().testTag("scanResults"),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(
                start = 16.dp,
                end = 16.dp,
                top = innerPadding.calculateTopPadding(),
                bottom = innerPadding.calculateBottomPadding() + 16.dp
            )
        ) {
            item(key = "hero") { ScanHero(state.status) }
            item(key = "stats") { ScanStats(state) }
            item(key = "actions") { ScanActions(state.status, onScanNow, onPause, onResume, onCancel, onScanFile) }
            item(key = "header") { SectionHeader(stringResource(R.string.scan_results_header)) }
            if (state.results.isEmpty()) {
                item(key = "empty") { EmptyState(DsR.drawable.bs_ic_apps, stringResource(R.string.scan_no_results)) }
            }
            items(state.results, key = {
                it.packageName
            }) { result -> ScanResultRow(result, onClick = { onResultClick(result.packageName) }) }
        }
    }
}

@Composable
private fun ScanHero(status: ScanStatus) {
    val (progress, color, icon) = heroVisuals(status)
    val percent = (progress * PERCENT).toInt()
    val runningDescription = stringResource(R.string.scan_progress_description, percent)
    val title = stringResource(heroTitle(status))
    val ringDescription = if (status is ScanStatus.Running) runningDescription else title
    BsCard(modifier = Modifier.padding(top = 8.dp)) {
        Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
            Box(
                modifier =
                    Modifier
                        .size(RING_SIZE.dp)
                        .clearAndSetSemantics { contentDescription = ringDescription },
                contentAlignment = Alignment.Center
            ) {
                ProgressRing(progress, color)
                if (status is ScanStatus.Running) {
                    Text(
                        stringResource(R.string.scan_percent, percent),
                        style = MaterialTheme.typography.headlineLarge,
                        color = color
                    )
                } else {
                    Icon(
                        painterResource(icon),
                        contentDescription = null,
                        tint = color,
                        modifier = Modifier.size(56.dp)
                    )
                }
            }
            Spacer(Modifier.height(12.dp))
            Text(
                title,
                style = MaterialTheme.typography.titleLarge,
                textAlign = TextAlign.Center,
                modifier = Modifier.testTag("scanProgress").semantics { liveRegion = LiveRegionMode.Polite }
            )
            val detail = (status as? ScanStatus.Running)?.currentApp
            if (detail != null) {
                Text(
                    detail,
                    style = LabelMono,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

private data class HeroVisuals(val progress: Float, val color: Color, val icon: Int)

private fun ScanStatus.hasThreats() = this is ScanStatus.Finished && malicious + suspicious > 0

@Composable
private fun heroVisuals(status: ScanStatus): HeroVisuals {
    val colors = BsTheme.status
    return when (status) {
        ScanStatus.Idle -> HeroVisuals(0f, MaterialTheme.colorScheme.primary, DsR.drawable.bs_ic_shield_check)

        is ScanStatus.Running ->
            HeroVisuals(
                if (status.total ==
                    0
                ) {
                    0f
                } else {
                    status.scanned.toFloat() / status.total
                },
                colors.info,
                DsR.drawable.bs_ic_radar
            )

        is ScanStatus.Finished ->
            if (status.hasThreats()) {
                HeroVisuals(1f, colors.danger, DsR.drawable.bs_ic_report)
            } else {
                HeroVisuals(1f, colors.safe, DsR.drawable.bs_ic_shield_check)
            }
    }
}

private fun heroTitle(status: ScanStatus): Int = when (status) {
    ScanStatus.Idle -> R.string.scan_ready
    is ScanStatus.Running -> if (status.paused) R.string.scan_paused else R.string.scan_running
    is ScanStatus.Finished -> if (status.hasThreats()) R.string.scan_done_threats else R.string.scan_done_clean
}

@Composable
private fun ProgressRing(progress: Float, color: Color) {
    val track = MaterialTheme.colorScheme.surfaceContainerHighest
    Canvas(Modifier.size(RING_SIZE.dp)) {
        val stroke = Stroke(width = 10.dp.toPx(), cap = StrokeCap.Round)
        drawArc(track, 0f, FULL_CIRCLE, useCenter = false, style = stroke)
        drawArc(color, START_ANGLE, FULL_CIRCLE * progress, useCenter = false, style = stroke)
    }
}

@Composable
private fun ScanStats(state: ScanUiState) {
    val status = state.status
    val checked =
        when (status) {
            is ScanStatus.Running -> stringResource(R.string.scan_count, status.scanned, status.total)
            is ScanStatus.Finished -> status.total.toString()
            ScanStatus.Idle -> state.results.size.toString()
        }
    val threats =
        when (status) {
            is ScanStatus.Running -> status.threats
            is ScanStatus.Finished -> status.malicious + status.suspicious
            ScanStatus.Idle -> state.results.count { it.verdict != Verdict.CLEAN }
        }
    Row(Modifier.fillMaxWidth().padding(top = 12.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        StatTile(checked, stringResource(R.string.scan_stat_apps), Modifier.weight(1f))
        StatTile(
            threats.toString(),
            stringResource(R.string.scan_stat_threats),
            Modifier.weight(1f),
            valueColor = if (threats > 0) BsTheme.status.danger else MaterialTheme.colorScheme.onSurface
        )
    }
}

@Composable
private fun ScanActions(
    status: ScanStatus,
    onScanNow: () -> Unit,
    onPause: () -> Unit,
    onResume: () -> Unit,
    onCancel: () -> Unit,
    onScanFile: () -> Unit
) {
    Column(Modifier.padding(top = 16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        if (status is ScanStatus.Running) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = if (status.paused) onResume else onPause,
                    modifier = Modifier.weight(1f).heightIn(min = 48.dp)
                ) {
                    Icon(
                        painterResource(if (status.paused) DsR.drawable.bs_ic_play else DsR.drawable.bs_ic_pause),
                        contentDescription = null
                    )
                    Spacer(Modifier.size(8.dp))
                    Text(stringResource(if (status.paused) R.string.scan_resume else R.string.scan_pause))
                }
                OutlinedButton(onClick = onCancel, modifier = Modifier.weight(1f).heightIn(min = 48.dp)) {
                    Text(stringResource(R.string.scan_cancel))
                }
            }
        } else {
            PrimaryActionButton(
                text = stringResource(if (status is ScanStatus.Finished) R.string.scan_again else R.string.scan_now),
                onClick = onScanNow,
                icon = DsR.drawable.bs_ic_radar,
                modifier = Modifier.testTag("scanNow")
            )
        }
        OutlinedButton(
            onClick = onScanFile,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("scanFile")
        ) {
            Icon(painterResource(DsR.drawable.bs_ic_file), contentDescription = null)
            Spacer(Modifier.size(8.dp))
            Text(stringResource(R.string.scan_file))
        }
    }
}

@Composable
private fun ScanResultRow(result: ScanResult, onClick: () -> Unit) {
    val status = BsTheme.status
    val (icon, tint) =
        when (result.verdict) {
            Verdict.MALICIOUS -> DsR.drawable.bs_ic_report to status.danger
            Verdict.SUSPICIOUS -> DsR.drawable.bs_ic_warning to status.caution
            Verdict.CLEAN -> DsR.drawable.bs_ic_check_circle to status.safe
        }
    ListRow(
        title = result.appLabel,
        subtitle = result.packageName,
        icon = icon,
        iconTint = tint,
        onClick = onClick,
        trailing = { VerdictChip(result.verdict) }
    )
}

private const val APK_MIME = "application/vnd.android.package-archive"
private const val RING_SIZE = 168
private const val PERCENT = 100
private const val FULL_CIRCLE = 360f
private const val START_ANGLE = -90f
