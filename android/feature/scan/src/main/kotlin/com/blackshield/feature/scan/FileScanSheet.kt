package com.blackshield.feature.scan

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.data.quarantine.QuarantineOutcome
import com.blackshield.core.designsystem.R as DsR
import com.blackshield.core.designsystem.component.IconTile
import com.blackshield.core.designsystem.component.PrimaryActionButton
import com.blackshield.core.designsystem.theme.BsTheme

/** The result of scanning one picked APK file, with "Quarantine" when it is harmful. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FileScanSheet(file: FileScanUi, onQuarantine: () -> Unit, onDismiss: () -> Unit) {
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 8.dp).testTag("fileScanSheet"),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                val (icon, tint) =
                    when (file.verdict) {
                        Verdict.MALICIOUS -> DsR.drawable.bs_ic_report to BsTheme.status.danger
                        Verdict.SUSPICIOUS -> DsR.drawable.bs_ic_warning to BsTheme.status.caution
                        Verdict.CLEAN -> DsR.drawable.bs_ic_check_circle to BsTheme.status.safe
                        null -> DsR.drawable.bs_ic_file to MaterialTheme.colorScheme.primary
                    }
                IconTile(icon, tint)
                Column(Modifier.weight(1f)) {
                    Text(file.name, style = MaterialTheme.typography.titleMedium)
                    file.verdict?.let { VerdictChip(it) }
                }
            }
            Body(file)
            Actions(file, onQuarantine, onDismiss)
        }
    }
}

@Composable
private fun Body(file: FileScanUi) {
    val message =
        when {
            file.unreadable -> stringResource(R.string.file_unreadable)
            file.scanning -> null
            file.quarantine == QuarantineOutcome.Quarantined -> stringResource(R.string.file_quarantined)
            file.quarantine == QuarantineOutcome.OriginalKept -> stringResource(R.string.file_original_kept)
            file.quarantine == QuarantineOutcome.Failed -> stringResource(R.string.file_quarantine_failed)
            file.verdict == Verdict.CLEAN -> stringResource(R.string.file_clean)
            else -> file.topReason.ifBlank { stringResource(R.string.file_harmful) }
        }
    if (message == null) {
        Text(stringResource(R.string.file_scanning), style = MaterialTheme.typography.bodyMedium)
        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
    } else {
        Text(
            message,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.semantics {
                liveRegion =
                    LiveRegionMode.Polite
            }
        )
    }
}

@Composable
private fun Actions(file: FileScanUi, onQuarantine: () -> Unit, onDismiss: () -> Unit) {
    val canQuarantine = file.threatId != null && file.quarantine == null
    if (canQuarantine) {
        PrimaryActionButton(
            text = stringResource(R.string.file_quarantine),
            onClick = onQuarantine,
            icon = DsR.drawable.bs_ic_lock,
            modifier = Modifier.testTag("quarantineFile")
        )
    }
    OutlinedButton(
        onClick = onDismiss,
        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).padding(bottom = 16.dp)
    ) {
        Text(stringResource(if (canQuarantine) R.string.file_later else R.string.file_close))
    }
}
