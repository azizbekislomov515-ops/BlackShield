package com.blackshield.feature.threats.history

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
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
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.blackshield.core.data.model.ScanSource
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.data.repository.HistoryPeriod
import com.blackshield.core.designsystem.R as DsR
import com.blackshield.core.designsystem.component.BsCard
import com.blackshield.core.designsystem.component.BsFilterChip
import com.blackshield.core.designsystem.component.BsTopBar
import com.blackshield.core.designsystem.component.EmptyState
import com.blackshield.core.designsystem.component.SectionHeader
import com.blackshield.core.ui.HistoryRow
import com.blackshield.core.ui.sourceLabel
import com.blackshield.feature.threats.R
import java.time.LocalDate

@Composable
fun HistoryRoute(onBack: () -> Unit, modifier: Modifier = Modifier, viewModel: HistoryViewModel = hiltViewModel()) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val resources = LocalResources.current
    val snackbar = remember { SnackbarHostState() }
    var pending by rememberSaveable { mutableStateOf<ExportFormat?>(null) }
    val saveJson =
        rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument(ExportFormat.JSON.mimeType)) { uri ->
            if (uri != null) viewModel.export(ExportFormat.JSON, uri)
        }
    val savePdf =
        rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument(ExportFormat.PDF.mimeType)) { uri ->
            if (uri != null) viewModel.export(ExportFormat.PDF, uri)
        }
    LaunchedEffect(Unit) {
        viewModel.exports.collect { saved ->
            snackbar.showSnackbar(resources.getString(if (saved) R.string.export_saved else R.string.export_failed))
        }
    }
    LaunchedEffect(pending) {
        val format = pending ?: return@LaunchedEffect
        val name = resources.getString(R.string.export_file_name, LocalDate.now().toString(), format.extension)
        if (format == ExportFormat.JSON) saveJson.launch(name) else savePdf.launch(name)
        pending = null
    }
    HistoryScreen(
        state = state,
        onBack = onBack,
        onPeriod = viewModel::setPeriod,
        onVerdict = viewModel::toggleVerdict,
        onSource = viewModel::toggleSource,
        onClearFilters = viewModel::clearFilters,
        onExport = { pending = it },
        snackbar = snackbar,
        modifier = modifier
    )
}

@Composable
fun HistoryScreen(
    state: HistoryUiState,
    onBack: () -> Unit,
    onPeriod: (HistoryPeriod) -> Unit,
    onVerdict: (Verdict) -> Unit,
    onSource: (ScanSource) -> Unit,
    onClearFilters: () -> Unit,
    onExport: (ExportFormat) -> Unit,
    modifier: Modifier = Modifier,
    snackbar: SnackbarHostState = remember { SnackbarHostState() }
) {
    Scaffold(
        modifier = modifier.fillMaxSize(),
        topBar = {
            BsTopBar(
                stringResource(R.string.history_title),
                onBack = onBack,
                backDescription = stringResource(R.string.back),
                actions = { ExportMenu(enabled = state.events.isNotEmpty(), onExport = onExport) }
            )
        },
        snackbarHost = { SnackbarHost(snackbar) }
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().testTag("history"),
            contentPadding = PaddingValues(
                start = 16.dp,
                end = 16.dp,
                top = padding.calculateTopPadding(),
                bottom = 24.dp
            ),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            item(key = "filters") { Filters(state, onPeriod, onVerdict, onSource, onClearFilters) }
            if (state.events.isEmpty()) {
                item(key = "empty") { EmptyState(DsR.drawable.bs_ic_history, stringResource(R.string.history_empty)) }
            }
            items(state.events, key = {
                it.id
            }) { event -> BsCard(contentPadding = 0.dp) { HistoryRow(event, state.now) } }
        }
    }
}

@Composable
private fun Filters(
    state: HistoryUiState,
    onPeriod: (HistoryPeriod) -> Unit,
    onVerdict: (Verdict) -> Unit,
    onSource: (ScanSource) -> Unit,
    onClear: () -> Unit
) {
    val filter = state.filter
    SectionHeader(stringResource(R.string.history_filter_date)) {
        if (filter.verdicts.isNotEmpty() || filter.sources.isNotEmpty() || filter.period != HistoryPeriod.ALL) {
            TextButton(onClick = onClear) { Text(stringResource(R.string.history_filter_clear)) }
        }
    }
    ChipRow {
        HistoryPeriod.entries.forEach { period ->
            BsFilterChip(
                selected = filter.period == period,
                onClick = { onPeriod(period) },
                label = stringResource(periodLabel(period)),
                modifier = Modifier.testTag("period_${period.name}")
            )
        }
    }
    SectionHeader(stringResource(R.string.history_filter_verdict))
    ChipRow {
        Verdict.entries.forEach { verdict ->
            BsFilterChip(
                selected = verdict in filter.verdicts,
                onClick = { onVerdict(verdict) },
                label = stringResource(verdictFilterLabel(verdict)),
                modifier = Modifier.testTag("verdict_${verdict.name}")
            )
        }
    }
    SectionHeader(stringResource(R.string.history_filter_source))
    ChipRow {
        ScanSource.entries.forEach { source ->
            BsFilterChip(
                selected = source in filter.sources,
                onClick = { onSource(source) },
                label = sourceLabel(source),
                modifier = Modifier.testTag("source_${source.name}")
            )
        }
    }
}

@Composable
private fun ChipRow(content: @Composable () -> Unit) {
    Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        content()
    }
}

@Composable
private fun ExportMenu(enabled: Boolean, onExport: (ExportFormat) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box {
        IconButton(onClick = { open = true }, enabled = enabled, modifier = Modifier.testTag("export")) {
            Icon(painterResource(DsR.drawable.bs_ic_download), contentDescription = stringResource(R.string.export))
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            DropdownMenuItem(text = { Text(stringResource(R.string.export_pdf)) }, onClick = {
                open = false
                onExport(ExportFormat.PDF)
            }, modifier = Modifier.padding(horizontal = 4.dp).testTag("exportPdf"))
            DropdownMenuItem(text = { Text(stringResource(R.string.export_json)) }, onClick = {
                open = false
                onExport(ExportFormat.JSON)
            }, modifier = Modifier.padding(horizontal = 4.dp).testTag("exportJson"))
        }
    }
}

private fun periodLabel(period: HistoryPeriod): Int = when (period) {
    HistoryPeriod.DAY -> R.string.period_day
    HistoryPeriod.WEEK -> R.string.period_week
    HistoryPeriod.MONTH -> R.string.period_month
    HistoryPeriod.ALL -> R.string.period_all
}

private fun verdictFilterLabel(verdict: Verdict): Int = when (verdict) {
    Verdict.CLEAN -> R.string.filter_clean
    Verdict.SUSPICIOUS -> R.string.filter_suspicious
    Verdict.MALICIOUS -> R.string.filter_malicious
}
