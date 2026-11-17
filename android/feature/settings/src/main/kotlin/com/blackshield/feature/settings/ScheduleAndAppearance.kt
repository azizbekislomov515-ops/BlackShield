package com.blackshield.feature.settings

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.blackshield.core.data.prefs.ScanFrequency
import com.blackshield.core.data.prefs.ScanSchedule
import com.blackshield.core.data.prefs.ThemeMode
import com.blackshield.core.designsystem.R as DsR
import com.blackshield.core.designsystem.component.BsFilterChip
import com.blackshield.core.designsystem.component.ListRow
import com.blackshield.core.designsystem.component.SwitchRow

/** How often the full scan runs, and under which conditions (both save battery). */
@Composable
internal fun ScheduleSection(schedule: ScanSchedule, onChange: (ScanSchedule) -> Unit) {
    ChipRow {
        ScanFrequency.entries.forEach { frequency ->
            BsFilterChip(
                selected = schedule.frequency == frequency,
                onClick = { onChange(schedule.copy(frequency = frequency)) },
                label = stringResource(frequencyLabel(frequency)),
                modifier = Modifier.testTag("frequency_${frequency.name}")
            )
        }
    }
    val enabled = schedule.frequency != ScanFrequency.OFF
    SwitchRow(
        title = stringResource(R.string.settings_schedule_charging),
        subtitle = stringResource(R.string.settings_schedule_charging_summary),
        checked = schedule.requiresCharging,
        onCheckedChange = { onChange(schedule.copy(requiresCharging = it)) },
        icon = DsR.drawable.bs_ic_battery_charging,
        enabled = enabled,
        testTag = "scheduleCharging"
    )
    SwitchRow(
        title = stringResource(R.string.settings_schedule_idle),
        subtitle = stringResource(R.string.settings_schedule_idle_summary),
        checked = schedule.requiresIdle,
        onCheckedChange = { onChange(schedule.copy(requiresIdle = it)) },
        icon = DsR.drawable.bs_ic_schedule,
        enabled = enabled,
        testTag = "scheduleIdle"
    )
}

/** Theme, and the app language (Android 13+ has a per-app setting; older versions follow the system). */
@Composable
internal fun AppearanceSection(theme: ThemeMode, onThemeChange: (ThemeMode) -> Unit) {
    val context = LocalContext.current
    ChipRow {
        ThemeMode.entries.forEach { mode ->
            BsFilterChip(
                selected = theme == mode,
                onClick = { onThemeChange(mode) },
                label = stringResource(themeLabel(mode)),
                modifier = Modifier.testTag("theme_${mode.name}")
            )
        }
    }
    val perAppLanguage = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
    ListRow(
        title = stringResource(R.string.settings_language),
        subtitle = stringResource(
            if (perAppLanguage) R.string.settings_language_summary else R.string.settings_language_system
        ),
        icon = DsR.drawable.bs_ic_globe,
        onClick = if (perAppLanguage) ({ openLanguageSettings(context) }) else null,
        modifier = Modifier.testTag("language")
    )
}

@Composable
private fun ChipRow(content: @Composable () -> Unit) {
    Row(
        Modifier.horizontalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) { content() }
}

private fun openLanguageSettings(context: Context) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
    val intent =
        Intent(Settings.ACTION_APP_LOCALE_SETTINGS, Uri.fromParts("package", context.packageName, null))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    try {
        context.startActivity(intent)
    } catch (_: ActivityNotFoundException) {
        context.startActivity(Intent(Settings.ACTION_LOCALE_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }
}

private fun frequencyLabel(frequency: ScanFrequency): Int = when (frequency) {
    ScanFrequency.OFF -> R.string.settings_frequency_off
    ScanFrequency.DAILY -> R.string.settings_frequency_daily
    ScanFrequency.WEEKLY -> R.string.settings_frequency_weekly
    ScanFrequency.MONTHLY -> R.string.settings_frequency_monthly
}

private fun themeLabel(mode: ThemeMode): Int = when (mode) {
    ThemeMode.SYSTEM -> R.string.settings_theme_system
    ThemeMode.LIGHT -> R.string.settings_theme_light
    ThemeMode.DARK -> R.string.settings_theme_dark
}

/** Crash reports: off until the user turns them on; what they contain is in the subtitle. */
@Composable
internal fun PrivacySection(crashReports: Boolean, onChange: (Boolean) -> Unit) {
    SwitchRow(
        title = stringResource(R.string.settings_crash_reports),
        subtitle = stringResource(R.string.settings_crash_reports_summary),
        checked = crashReports,
        onCheckedChange = onChange,
        icon = DsR.drawable.bs_ic_report,
        testTag = "crashReports"
    )
}
