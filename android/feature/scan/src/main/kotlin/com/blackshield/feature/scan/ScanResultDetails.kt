package com.blackshield.feature.scan

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.blackshield.core.data.model.ScanReason
import com.blackshield.core.data.model.ScanResult
import com.blackshield.core.data.model.Verdict
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

@Composable
fun VerdictChip(verdict: Verdict, modifier: Modifier = Modifier) {
    val colors = MaterialTheme.colorScheme
    val (label, container, content) =
        when (verdict) {
            Verdict.CLEAN -> Triple(R.string.verdict_clean, colors.secondaryContainer, colors.onSecondaryContainer)

            Verdict.SUSPICIOUS ->
                Triple(R.string.verdict_suspicious, colors.tertiaryContainer, colors.onTertiaryContainer)

            Verdict.MALICIOUS -> Triple(R.string.verdict_malicious, colors.errorContainer, colors.onErrorContainer)
        }
    Surface(color = container, contentColor = content, shape = RoundedCornerShape(8.dp), modifier = modifier) {
        Text(
            text = stringResource(label),
            style = MaterialTheme.typography.labelLarge,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanResultDetailsSheet(
    result: ScanResult,
    trusted: Boolean,
    onTrustedChange: (Boolean) -> Unit,
    onDismiss: () -> Unit
) {
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 24.dp, vertical = 8.dp)
                    .testTag("resultDetails"),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(result.appLabel, style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
                VerdictChip(result.verdict)
            }
            Field(stringResource(R.string.details_package), result.packageName)
            Field(stringResource(R.string.details_version), result.versionCode.toString())
            Field(
                stringResource(R.string.details_sha256),
                result.apkSha256 ?: stringResource(R.string.details_sha256_unavailable),
                monospace = true
            )
            Field(stringResource(R.string.details_risk), stringResource(R.string.details_risk_value, result.riskScore))
            Field(
                stringResource(R.string.details_scanned_at),
                DATE_FORMAT.format(Instant.ofEpochMilli(result.scannedAt))
            )

            Text(stringResource(R.string.details_reasons), style = MaterialTheme.typography.titleSmall)
            if (result.reasons.isEmpty()) {
                Text(stringResource(R.string.details_no_reasons), style = MaterialTheme.typography.bodyMedium)
            }
            result.reasons.forEach { reason -> ReasonRow(reason) }

            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.details_trust), style = MaterialTheme.typography.bodyLarge)
                    Text(stringResource(R.string.details_trust_hint), style = MaterialTheme.typography.bodySmall)
                }
                Switch(checked = trusted, onCheckedChange = onTrustedChange)
            }
        }
    }
}

@Composable
private fun Field(label: String, value: String, monospace: Boolean = false) {
    Column {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        SelectionContainer {
            Text(
                value,
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = if (monospace) FontFamily.Monospace else null
            )
        }
    }
}

@Composable
private fun ReasonRow(reason: ScanReason) {
    val text =
        when (reason.code) {
            ScanReason.Code.KNOWN_MALWARE -> stringResource(R.string.reason_known_malware, reason.detail)
            ScanReason.Code.SIDELOADED -> stringResource(R.string.reason_sideloaded, reason.detail)
            ScanReason.Code.SMS_ACCESS -> stringResource(R.string.reason_sms_access, reason.detail)
            ScanReason.Code.INSTALLS_PACKAGES -> stringResource(R.string.reason_installs_packages)
            ScanReason.Code.DRAWS_OVER_APPS -> stringResource(R.string.reason_draws_over_apps)
            ScanReason.Code.DEBUGGABLE -> stringResource(R.string.reason_debuggable)
            ScanReason.Code.ALLOW_LISTED -> stringResource(R.string.reason_allow_listed, reason.detail)
            ScanReason.Code.HASH_FAILED -> stringResource(R.string.reason_hash_failed, reason.detail)
        }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(text, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        if (reason.points > 0) {
            Text(
                stringResource(R.string.reason_points, reason.points),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

private val DATE_FORMAT: DateTimeFormatter =
    DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM).withZone(ZoneId.systemDefault())
