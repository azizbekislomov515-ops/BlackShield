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

/** A quarantined file, with Restore and Delete. */
@Composable
internal fun VaultRow(file: FileThreat, actions: ThreatActions) {
    BsCard(contentPadding = 0.dp) {
        ListRow(
            title = file.appLabel ?: file.displayName,
            subtitle = fileMeta(file),
            icon = DsR.drawable.bs_ic_lock,
            iconTint = BsTheme.status.info
        )
        Row(
            Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            OutlinedButton(onClick = {
                actions.onRestore(file)
            }, modifier = Modifier.weight(1f).heightIn(min = 48.dp).testTag("restore")) {
                Text(stringResource(R.string.threats_restore))
            }
            DangerButton(stringResource(R.string.threats_delete), Modifier.weight(1f).testTag("delete")) {
                actions.onDelete(file)
            }
        }
    }
}

/** The file name (when the title is the app's name) and the size, e.g. "update.apk · 5.1 MB". */
@Composable
internal fun fileMeta(file: FileThreat): String {
    val size = Formatter.formatShortFileSize(LocalContext.current, file.sizeBytes)
    return if (file.appLabel == null) size else stringResource(R.string.threats_file_meta, file.displayName, size)
}
