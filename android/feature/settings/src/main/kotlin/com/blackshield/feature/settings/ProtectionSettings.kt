package com.blackshield.feature.settings

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.DocumentsContract
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.core.net.toUri
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import timber.log.Timber

/** Real-time protection settings. Each permission is explained before it is requested. */
@Composable
internal fun RealTimeProtectionSection(
    state: SettingsUiState,
    onRealTimeProtectionChange: (Boolean) -> Unit,
    onWatchDownloadsChange: (Boolean) -> Unit,
    onFolderAdded: (String) -> Unit,
    onFolderRemoved: (String) -> Unit,
    onOpenTroubleshooting: () -> Unit
) {
    // Grants change in system settings; re-check whenever the screen comes back.
    var resumes by remember { mutableIntStateOf(0) }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { resumes++ }
    ProtectionRows(state.realTimeProtectionEnabled, resumes, onRealTimeProtectionChange) { resumes++ }
    DownloadsRows(state.watchDownloads, resumes, onWatchDownloadsChange) { resumes++ }
    FolderRows(state.watchedFolders, onFolderAdded, onFolderRemoved, onOpenTroubleshooting)
}

/** The protection switch; turning it on asks for notifications (Android 13+), which warnings need. */
@Composable
private fun ProtectionRows(enabled: Boolean, resumes: Int, onChange: (Boolean) -> Unit, onGrantChanged: () -> Unit) {
    val context = LocalContext.current
    val granted = remember(resumes) { notificationsGranted(context) }
    val request = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { onGrantChanged() }
    val askForNotifications = {
        if (Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.TIRAMISU
        ) {
            request.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
    SwitchRow(
        title = stringResource(R.string.settings_real_time_protection),
        summary = stringResource(R.string.settings_real_time_protection_summary),
        checked = enabled,
        onCheckedChange = { on ->
            onChange(on)
            if (on && !granted) askForNotifications()
        }
    )
    if (enabled && !granted) {
        WarningRow(
            stringResource(R.string.settings_notifications_missing),
            stringResource(R.string.settings_allow),
            "notificationsMissing"
        ) {
            askForNotifications()
            // A permanently denied permission shows no dialog; the settings screen always works.
            open(
                context,
                Intent(
                    Settings.ACTION_APP_NOTIFICATION_SETTINGS
                ).putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
            )
        }
    }
}

/** Checking Downloads: All files access on Android 11+ (explained first), READ_EXTERNAL_STORAGE before. */
@Composable
private fun DownloadsRows(watch: Boolean, resumes: Int, onChange: (Boolean) -> Unit, onGrantChanged: () -> Unit) {
    val context = LocalContext.current
    val access = remember(resumes) { downloadsAccessGranted(context) }
    var explainAllFiles by remember { mutableStateOf(false) }
    val requestRead =
        rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { onGrantChanged() }
    val askForAccess = {
        if (Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.R
        ) {
            explainAllFiles = true
        } else {
            requestRead.launch(Manifest.permission.READ_EXTERNAL_STORAGE)
        }
    }
    SwitchRow(
        title = stringResource(R.string.settings_watch_downloads),
        summary = stringResource(R.string.settings_watch_downloads_summary),
        checked = watch,
        onCheckedChange = { on ->
            onChange(on)
            if (on && !access) askForAccess()
        }
    )
    if (watch && !access) {
        WarningRow(
            stringResource(R.string.settings_downloads_access_missing),
            stringResource(R.string.settings_allow),
            "downloadsAccessMissing"
        ) {
            askForAccess()
        }
    }
    if (explainAllFiles) {
        AllFilesAccessDialog(onDismiss = { explainAllFiles = false }) {
            explainAllFiles = false
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val pkg = Uri.fromParts("package", context.packageName, null)
                open(context, Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, pkg))
            }
        }
    }
}

@Composable
private fun AllFilesAccessDialog(onDismiss: () -> Unit, onContinue: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.settings_all_files_title)) },
        text = { Text(stringResource(R.string.settings_all_files_body)) },
        confirmButton = { TextButton(onClick = onContinue) { Text(stringResource(R.string.settings_continue)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.settings_not_now)) } }
    )
}

/** Folders picked with the Storage Access Framework: no storage permission needed. */
@Composable
private fun FolderRows(
    folders: List<String>,
    onAdded: (String) -> Unit,
    onRemoved: (String) -> Unit,
    onOpenTroubleshooting: () -> Unit
) {
    val context = LocalContext.current
    val pickFolder =
        rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
            uri ?: return@rememberLauncherForActivityResult
            // Keep read access across restarts; without it the folder cannot be watched after a reboot.
            context.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            onAdded(uri.toString())
        }
    ListItem(
        headlineContent = { Text(stringResource(R.string.settings_watched_folders)) },
        supportingContent = { Text(stringResource(R.string.settings_watched_folders_summary)) }
    )
    folders.forEach { folder ->
        Row(
            modifier = Modifier.fillMaxWidth().padding(start = 32.dp, end = 16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(folderName(folder), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
            TextButton(onClick = {
                runCatching {
                    context.contentResolver.releasePersistableUriPermission(
                        folder.toUri(),
                        Intent.FLAG_GRANT_READ_URI_PERMISSION
                    )
                }
                onRemoved(folder)
            }) { Text(stringResource(R.string.settings_remove_folder)) }
        }
    }
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        OutlinedButton(onClick = { pickFolder.launch(null) }, modifier = Modifier.testTag("addFolder")) {
            Text(stringResource(R.string.settings_add_folder))
        }
        OutlinedButton(onClick = onOpenTroubleshooting, modifier = Modifier.testTag("troubleshooting")) {
            Text(stringResource(R.string.settings_troubleshooting))
        }
    }
}

@Composable
private fun WarningRow(text: String, action: String, tag: String, onAction: () -> Unit) {
    Column(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp).testTag(tag)) {
        Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
        TextButton(onClick = onAction) { Text(action) }
    }
}

private fun notificationsGranted(context: Context): Boolean = Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
    ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) ==
    PackageManager.PERMISSION_GRANTED

/** All files access on Android 11+ (see docs/permissions.md); READ_EXTERNAL_STORAGE before. */
private fun downloadsAccessGranted(context: Context): Boolean = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
    Environment.isExternalStorageManager()
} else {
    ContextCompat.checkSelfPermission(context, Manifest.permission.READ_EXTERNAL_STORAGE) ==
        PackageManager.PERMISSION_GRANTED
}

/** "primary:Download/Telegram" -> "Download/Telegram". */
private fun folderName(treeUri: String): String = runCatching {
    DocumentsContract.getTreeDocumentId(treeUri.toUri()).substringAfter(':').ifEmpty { "/" }
}.getOrDefault(treeUri)

private fun open(context: Context, intent: Intent) {
    try {
        context.startActivity(intent)
    } catch (e: ActivityNotFoundException) {
        Timber.w(e, "No activity for %s", intent.action)
    }
}
