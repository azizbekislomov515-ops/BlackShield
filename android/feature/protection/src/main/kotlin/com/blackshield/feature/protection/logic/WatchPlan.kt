package com.blackshield.feature.protection.logic

/** How the Downloads folder is watched for new APK files. */
enum class DownloadsWatch {
    /** The user has not asked for it. */
    OFF,

    /** Android 10 and older: inotify (FileObserver) on the real path, with READ_EXTERNAL_STORAGE. */
    FILE_OBSERVER,

    /**
     * Android 11+: a MediaStore observer. Shared storage is a FUSE mount there and inotify does not
     * see writes made by other apps reliably; MediaProvider indexes every file created on it.
     * Other apps' APKs are only visible with All files access.
     */
    MEDIA_STORE,

    /** Wanted, but the required storage access is missing: the UI asks for it. */
    MISSING_PERMISSION
}

data class WatchPlan(val downloads: DownloadsWatch, val folders: List<String>)

object WatchPlanner {
    /** Android 11 (API 30): scoped storage is enforced and inotify on shared storage is unreliable. */
    const val SCOPED_STORAGE_SDK = 30

    /**
     * @param hasAllFilesAccess MANAGE_EXTERNAL_STORAGE granted (API 30+).
     * @param hasLegacyRead READ_EXTERNAL_STORAGE granted (enough up to API 29).
     * @param folders SAF tree URIs the user picked; watched through their document provider on every
     *   API level, no storage permission needed.
     */
    fun plan(
        sdkInt: Int,
        watchDownloads: Boolean,
        hasAllFilesAccess: Boolean,
        hasLegacyRead: Boolean,
        folders: Set<String>
    ): WatchPlan {
        val downloads =
            when {
                !watchDownloads -> DownloadsWatch.OFF
                sdkInt >= SCOPED_STORAGE_SDK && hasAllFilesAccess -> DownloadsWatch.MEDIA_STORE
                sdkInt < SCOPED_STORAGE_SDK && hasLegacyRead -> DownloadsWatch.FILE_OBSERVER
                else -> DownloadsWatch.MISSING_PERMISSION
            }
        return WatchPlan(downloads, folders.sorted())
    }
}

object ApkNames {
    const val APK_MIME = "application/vnd.android.package-archive"

    fun isApk(displayName: String?, mimeType: String?): Boolean =
        mimeType == APK_MIME || displayName?.endsWith(".apk", ignoreCase = true) == true
}

/**
 * Where to resume PackageManager.getChangedPackages() after the service was not running. The
 * sequence number restarts at 0 on every boot, so it is stored with the boot count.
 */
object PackageCatchUp {
    data class Cursor(val bootCount: Int, val sequence: Int)

    /** The sequence to query from, or null on the very first start (nothing to catch up on). */
    fun startSequence(stored: Cursor?, currentBootCount: Int): Int? = when {
        stored == null -> null

        stored.bootCount != currentBootCount -> 0

        // rebooted: every change since boot
        else -> stored.sequence
    }
}
