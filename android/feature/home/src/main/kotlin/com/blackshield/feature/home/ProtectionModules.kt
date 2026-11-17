package com.blackshield.feature.home

import androidx.compose.foundation.layout.padding
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.blackshield.core.data.prefs.ScanFrequency
import com.blackshield.core.designsystem.R as DsR
import com.blackshield.core.designsystem.component.BsCard
import com.blackshield.core.designsystem.component.ListRow
import com.blackshield.core.designsystem.component.StatusChip
import com.blackshield.core.designsystem.component.SwitchRow
import com.blackshield.core.designsystem.theme.BsTheme
import com.blackshield.core.ui.relativeTime
import com.blackshield.feature.webshield.WebShieldStatus

/** The protection layers, each with its state and a way to change it. */
@Composable
internal fun ProtectionModules(state: HomeUiState, actions: HomeActions) {
    val status = BsTheme.status
    BsCard(contentPadding = 0.dp) {
        SwitchRow(
            title = stringResource(R.string.module_real_time),
            subtitle = stringResource(R.string.module_real_time_summary),
            checked = state.realTimeEnabled,
            onCheckedChange = actions.onRealTimeChange,
            icon = DsR.drawable.bs_ic_bolt,
            iconTint = if (state.realTimeEnabled) status.safe else status.caution,
            testTag = "moduleRealTime"
        )
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = DIVIDER_ALPHA))
        val webOn = state.webShield is WebShieldStatus.On
        ListRow(
            title = stringResource(R.string.module_web_shield),
            subtitle = stringResource(if (webOn) R.string.module_web_shield_on else R.string.module_web_shield_off),
            icon = DsR.drawable.bs_ic_globe,
            iconTint = if (webOn) status.safe else status.caution,
            onClick = actions.navigation.onOpenWebShield,
            trailing = { OnOffChip(webOn) },
            modifier = Modifier.testTag("moduleWebShield")
        )
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = DIVIDER_ALPHA))
        val scheduled = state.scanFrequency != ScanFrequency.OFF
        ListRow(
            title = stringResource(R.string.module_schedule),
            subtitle = stringResource(frequencyLabel(state.scanFrequency)),
            icon = DsR.drawable.bs_ic_schedule,
            iconTint = if (scheduled) status.safe else status.caution,
            onClick = actions.navigation.onOpenSchedule,
            trailing = { OnOffChip(scheduled) },
            modifier = Modifier.testTag("moduleSchedule")
        )
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = DIVIDER_ALPHA))
        val updated =
            state.definitionsUpdatedAt?.let { relativeTime(it, state.now) } ?: stringResource(R.string.home_never)
        ListRow(
            title = stringResource(R.string.module_definitions, state.definitionsVersion),
            subtitle =
                pluralStringResource(
                    R.plurals.module_definitions_summary,
                    state.signatureCount.toInt(),
                    state.signatureCount,
                    updated
                ),
            icon = DsR.drawable.bs_ic_database,
            iconTint = status.info,
            onClick = actions.onUpdateDefinitions,
            trailing = {
                if (state.definitionsUpdating) StatusChip(stringResource(R.string.fix_updating), status.info)
            },
            modifier = Modifier.testTag("moduleDefinitions")
        )
    }
}

@Composable
private fun OnOffChip(on: Boolean) {
    StatusChip(
        stringResource(if (on) R.string.module_on else R.string.module_off),
        if (on) BsTheme.status.safe else MaterialTheme.colorScheme.onSurfaceVariant
    )
}

internal fun frequencyLabel(frequency: ScanFrequency): Int = when (frequency) {
    ScanFrequency.OFF -> R.string.frequency_off
    ScanFrequency.DAILY -> R.string.frequency_daily
    ScanFrequency.WEEKLY -> R.string.frequency_weekly
    ScanFrequency.MONTHLY -> R.string.frequency_monthly
}

private const val DIVIDER_ALPHA = 0.4f
