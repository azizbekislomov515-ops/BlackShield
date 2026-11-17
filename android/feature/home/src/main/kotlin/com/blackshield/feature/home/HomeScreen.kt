package com.blackshield.feature.home

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.blackshield.core.designsystem.R as DsR
import com.blackshield.core.designsystem.component.BsCard
import com.blackshield.core.designsystem.component.EmptyState
import com.blackshield.core.designsystem.component.IconTile
import com.blackshield.core.designsystem.component.PrimaryActionButton
import com.blackshield.core.designsystem.component.ScoreRing
import com.blackshield.core.designsystem.component.SectionHeader
import com.blackshield.core.designsystem.component.StatusChip
import com.blackshield.core.designsystem.theme.BsTheme
import com.blackshield.core.designsystem.theme.LabelMono
import com.blackshield.core.ui.HistoryRow
import com.blackshield.core.ui.relativeTime
import com.blackshield.feature.scan.ScanStatus

/** Where the dashboard sends the user. */
data class HomeNavigation(
    val onOpenScan: () -> Unit,
    val onOpenThreats: () -> Unit,
    val onOpenWebShield: () -> Unit,
    val onOpenSchedule: () -> Unit,
    val onOpenHistory: () -> Unit
)

@Composable
fun HomeRoute(navigation: HomeNavigation, modifier: Modifier = Modifier, viewModel: HomeViewModel = hiltViewModel()) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    HomeScreen(
        state = state,
        actions =
            HomeActions(
                onScanNow = {
                    viewModel.scanNow()
                    navigation.onOpenScan()
                },
                onRealTimeChange = viewModel::setRealTimeProtection,
                onUpdateDefinitions = viewModel::updateDefinitions,
                navigation = navigation
            ),
        modifier = modifier
    )
}

data class HomeActions(
    val onScanNow: () -> Unit,
    val onRealTimeChange: (Boolean) -> Unit,
    val onUpdateDefinitions: () -> Unit,
    val navigation: HomeNavigation
)

@Composable
fun HomeScreen(state: HomeUiState, actions: HomeActions, modifier: Modifier = Modifier) {
    Scaffold(modifier = modifier.fillMaxSize()) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().testTag("home"),
            contentPadding = PaddingValues(
                start = 16.dp,
                end = 16.dp,
                top = padding.calculateTopPadding() + 8.dp,
                bottom = 24.dp
            )
        ) {
            item(key = "header") { Header(state) }
            item(key = "hero") { Hero(state, actions) }
            item(key = "score") { ScoreCard(state, actions) }
            item(key = "protection") { SectionHeader(stringResource(R.string.home_protection)) }
            item(key = "modules") { ProtectionModules(state, actions) }
            item(key = "activity") {
                SectionHeader(stringResource(R.string.home_activity)) {
                    TextButton(onClick = actions.navigation.onOpenHistory) {
                        Text(stringResource(R.string.home_history))
                    }
                }
            }
            if (state.recent.isEmpty()) {
                item(key = "noActivity") {
                    EmptyState(DsR.drawable.bs_ic_history, stringResource(R.string.home_no_activity))
                }
            }
            items(state.recent, key = { it.id }) { event ->
                BsCard(modifier = Modifier.padding(bottom = 8.dp), contentPadding = 0.dp) {
                    HistoryRow(event, state.now)
                }
            }
        }
    }
}

@Composable
private fun Header(state: HomeUiState) {
    val (label, color) = levelLabel(state.score.level)
    Row(Modifier.fillMaxWidth().padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(
            stringResource(R.string.home_app_name),
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.weight(1f).semantics { heading() }
        )
        StatusChip(stringResource(label), color, modifier = Modifier.testTag("protectionLevel"))
    }
}

@Composable
private fun levelLabel(level: ProtectionLevel): Pair<Int, Color> = when (level) {
    ProtectionLevel.PROTECTED -> R.string.home_level_protected to BsTheme.status.safe
    ProtectionLevel.ATTENTION -> R.string.home_level_attention to BsTheme.status.caution
    ProtectionLevel.AT_RISK -> R.string.home_level_risk to BsTheme.status.danger
}

@Composable
private fun Hero(state: HomeUiState, actions: HomeActions) {
    val (icon, title, color) =
        when (state.score.level) {
            ProtectionLevel.PROTECTED -> Triple(
                DsR.drawable.bs_ic_shield_check,
                R.string.home_title_protected,
                BsTheme.status.safe
            )

            ProtectionLevel.ATTENTION -> Triple(
                DsR.drawable.bs_ic_shield,
                R.string.home_title_attention,
                BsTheme.status.caution
            )

            ProtectionLevel.AT_RISK -> Triple(
                DsR.drawable.bs_ic_report,
                R.string.home_title_risk,
                BsTheme.status.danger
            )
        }
    BsCard {
        Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
            IconTile(icon, color, size = 88.dp)
            Spacer(Modifier.height(12.dp))
            Text(
                stringResource(title),
                style = MaterialTheme.typography.headlineMedium,
                modifier = Modifier.semantics {
                    heading()
                }
            )
            val lastScan = state.lastScanAt?.let { relativeTime(it, state.now) } ?: stringResource(R.string.home_never)
            Text(
                stringResource(R.string.home_meta, lastScan, state.definitionsVersion),
                style = LabelMono,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp)
            )
            Spacer(Modifier.height(16.dp))
            when (val scan = state.scan) {
                is ScanStatus.Running -> {
                    Text(
                        stringResource(R.string.home_scanning, scan.scanned, scan.total),
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.testTag("homeScanProgress")
                    )
                    LinearProgressIndicator(
                        progress = { if (scan.total == 0) 0f else scan.scanned.toFloat() / scan.total },
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
                    )
                    TextButton(onClick = actions.navigation.onOpenScan) {
                        Text(stringResource(R.string.home_view_scan))
                    }
                }

                else -> PrimaryActionButton(
                    text = stringResource(R.string.home_scan_now),
                    onClick = actions.onScanNow,
                    icon = DsR.drawable.bs_ic_radar,
                    modifier = Modifier.testTag("homeScanNow")
                )
            }
            if (state.openThreats > 0) {
                TextButton(
                    onClick = actions.navigation.onOpenThreats,
                    modifier = Modifier.testTag("homeReviewThreats")
                ) {
                    Text(
                        androidx.compose.ui.res.pluralStringResource(
                            R.plurals.home_review_threats,
                            state.openThreats,
                            state.openThreats
                        )
                    )
                }
            }
        }
    }
}

@Composable
private fun ScoreCard(state: HomeUiState, actions: HomeActions) {
    val score = state.score
    val color =
        when (score.level) {
            ProtectionLevel.PROTECTED -> BsTheme.status.safe
            ProtectionLevel.ATTENTION -> BsTheme.status.caution
            ProtectionLevel.AT_RISK -> BsTheme.status.danger
        }
    BsCard(modifier = Modifier.padding(top = 12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(
                    stringResource(R.string.home_score).uppercase(),
                    style = LabelMono,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(stringResource(scoreHeadline(score.total)), style = MaterialTheme.typography.titleLarge)
                Text(
                    stringResource(R.string.home_score_explained),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            ScoreRing(
                score.total,
                color,
                description = stringResource(R.string.home_score_description, score.total),
                modifier = Modifier.testTag("securityScore")
            )
        }
        if (score.improvements.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            score.improvements.forEach { item -> ImprovementRow(item, state, actions) }
        }
    }
}

private fun scoreHeadline(total: Int): Int = when {
    total >= EXCELLENT -> R.string.home_score_excellent
    total >= GOOD -> R.string.home_score_good
    total >= FAIR -> R.string.home_score_fair
    else -> R.string.home_score_poor
}

/** One reason the score is not 100, with the action that fixes it. */
@Composable
private fun ImprovementRow(item: ScoreItem, state: HomeUiState, actions: HomeActions) {
    val nav = actions.navigation
    val (text, action, onClick) =
        when (item.factor) {
            ScoreFactor.REAL_TIME -> Triple(R.string.fix_real_time, R.string.fix_turn_on) {
                actions.onRealTimeChange(true)
            }

            ScoreFactor.THREATS -> Triple(R.string.fix_threats, R.string.fix_review, nav.onOpenThreats)

            ScoreFactor.RECENT_SCAN -> Triple(R.string.fix_scan, R.string.fix_scan_now, actions.onScanNow)

            ScoreFactor.DEFINITIONS -> Triple(
                R.string.fix_definitions,
                R.string.fix_update,
                actions.onUpdateDefinitions
            )

            ScoreFactor.WEB_SHIELD -> Triple(R.string.fix_web_shield, R.string.fix_turn_on, nav.onOpenWebShield)

            ScoreFactor.SCHEDULE -> Triple(R.string.fix_schedule, R.string.fix_set_up, nav.onOpenSchedule)
        }
    val gain = item.factor.max - item.earned
    val updating = item.factor == ScoreFactor.DEFINITIONS && state.definitionsUpdating
    // The whole row is the button: one big target, read by TalkBack as one item.
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .clip(MaterialTheme.shapes.small)
            .clickable(enabled = !updating, role = Role.Button, onClick = onClick)
            .padding(vertical = 4.dp)
            .testTag("improve_${item.factor.name}"),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text(stringResource(R.string.fix_points, gain), style = LabelMono, color = BsTheme.status.caution)
        Text(stringResource(text), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        Text(
            stringResource(if (updating) R.string.fix_updating else action),
            style = MaterialTheme.typography.labelLarge,
            color = if (updating) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.primary,
            modifier = Modifier.padding(horizontal = 8.dp)
        )
    }
}

private const val EXCELLENT = 90
private const val GOOD = 75
private const val FAIR = 50
