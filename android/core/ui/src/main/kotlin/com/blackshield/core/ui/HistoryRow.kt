package com.blackshield.core.ui

import android.content.res.Resources
import android.text.format.DateUtils
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.res.stringResource
import com.blackshield.core.data.model.HistoryEvent
import com.blackshield.core.data.model.HistoryKind
import com.blackshield.core.data.model.ScanSource
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.designsystem.R as DsR
import com.blackshield.core.designsystem.component.ListRow
import com.blackshield.core.designsystem.theme.BsTheme

/** "5 min ago", "Yesterday": localized by the system. */
fun relativeTime(at: Long, now: Long): String = DateUtils.getRelativeTimeSpanString(
    at,
    now,
    DateUtils.MINUTE_IN_MILLIS,
    DateUtils.FORMAT_ABBREV_RELATIVE
).toString()

/** One history line, the same on Home and in History. */
@Composable
fun HistoryRow(event: HistoryEvent, now: Long, modifier: Modifier = Modifier, onClick: (() -> Unit)? = null) {
    val status = BsTheme.status
    val (icon, tint) =
        when {
            event.kind == HistoryKind.QUARANTINED -> DsR.drawable.bs_ic_lock to status.info

            event.kind == HistoryKind.RESTORED -> DsR.drawable.bs_ic_restore to status.caution

            event.kind == HistoryKind.DELETED || event.kind == HistoryKind.UNINSTALLED ->
                DsR.drawable.bs_ic_delete to
                    status.info

            event.verdict == Verdict.MALICIOUS -> DsR.drawable.bs_ic_report to status.danger

            event.verdict == Verdict.SUSPICIOUS -> DsR.drawable.bs_ic_warning to status.caution

            else -> DsR.drawable.bs_ic_check_circle to status.safe
        }
    ListRow(
        title = historyTitle(event),
        subtitle = stringResource(
            R.string.history_meta,
            sourceLabel(event.source),
            relativeTime(event.occurredAt, now)
        ),
        icon = icon,
        iconTint = tint,
        onClick = onClick,
        modifier = modifier
    )
}

@Composable
fun historyTitle(event: HistoryEvent): String = HistoryText.title(LocalResources.current, event)

@Composable
fun verdictLabel(verdict: Verdict): String = HistoryText.verdict(LocalResources.current, verdict)

@Composable
fun sourceLabel(source: ScanSource): String = HistoryText.source(LocalResources.current, source)

/** Localized history text outside Compose too (the exported PDF report). */
object HistoryText {
    fun title(res: Resources, event: HistoryEvent): String = when (event.kind) {
        HistoryKind.SCAN_COMPLETED ->
            if (event.threatsFound == 0) {
                res.getQuantityString(R.plurals.history_scan_clean, event.itemsScanned, event.itemsScanned)
            } else {
                res.getQuantityString(R.plurals.history_scan_threats, event.threatsFound, event.threatsFound)
            }

        HistoryKind.ITEM_CHECKED -> res.getString(R.string.history_checked, event.subject, verdict(res, event.verdict))

        HistoryKind.QUARANTINED -> res.getString(R.string.history_quarantined, event.subject)

        HistoryKind.RESTORED -> res.getString(R.string.history_restored, event.subject)

        HistoryKind.DELETED -> res.getString(R.string.history_deleted, event.subject)

        HistoryKind.UNINSTALLED -> res.getString(R.string.history_uninstalled, event.subject)
    }

    fun verdict(res: Resources, verdict: Verdict): String = res.getString(
        when (verdict) {
            Verdict.CLEAN -> R.string.ui_verdict_clean
            Verdict.SUSPICIOUS -> R.string.ui_verdict_suspicious
            Verdict.MALICIOUS -> R.string.ui_verdict_malicious
        }
    )

    fun source(res: Resources, source: ScanSource): String = res.getString(
        when (source) {
            ScanSource.MANUAL -> R.string.source_manual
            ScanSource.SCHEDULED -> R.string.source_scheduled
            ScanSource.REAL_TIME -> R.string.source_real_time
            ScanSource.FILE -> R.string.source_file
        }
    )
}
