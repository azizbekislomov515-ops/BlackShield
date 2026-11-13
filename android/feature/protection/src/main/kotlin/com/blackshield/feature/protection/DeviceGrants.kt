package com.blackshield.feature.protection

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Environment
import android.provider.Settings
import androidx.core.content.ContextCompat

/** One-shot reads of grants and device facts used by the service and the troubleshooting screen. */
internal object DeviceGrants {
    /** All files access (MANAGE_EXTERNAL_STORAGE), Android 11+. */
    fun hasAllFilesAccess(): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && Environment.isExternalStorageManager()

    /** READ_EXTERNAL_STORAGE; enough for Downloads up to Android 10. */
    fun hasLegacyRead(context: Context): Boolean =
        ContextCompat.checkSelfPermission(context, Manifest.permission.READ_EXTERNAL_STORAGE) ==
            PackageManager.PERMISSION_GRANTED

    /** Changes on every boot; PackageManager change sequence numbers restart with it. */
    fun bootCount(context: Context): Int =
        Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT, 0)
}
