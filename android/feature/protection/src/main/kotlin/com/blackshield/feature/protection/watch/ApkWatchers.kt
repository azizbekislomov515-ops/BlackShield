package com.blackshield.feature.protection.watch

import android.content.ContentResolver
import android.content.ContentUris
import android.content.Context
import android.database.ContentObserver
import android.database.Cursor
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.FileObserver
import android.os.Handler
import android.os.Looper
import android.provider.DocumentsContract
import android.provider.MediaStore
import androidx.annotation.RequiresApi
import com.blackshield.core.scanner.files.ApkCandidate
import com.blackshield.feature.protection.ProtectionStateStore
import com.blackshield.feature.protection.logic.ApkNames
import com.blackshield.feature.protection.logic.KeyedDebouncer
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import timber.log.Timber

/** Reports new APK files. Event-driven: no polling. */
interface ApkWatcher {
    fun start()

    fun stop()
}

/**
 * Android 11+: watches the Downloads folder through MediaStore. MediaProvider indexes every file
 * created on shared storage (browser downloads, file managers, adb), and GENERATION_MODIFIED gives
 * an exact "changed since" cursor that survives restarts. Requires All files access to see other
 * apps' APKs.
 *
 * Pending rows are included on purpose: files written straight through the FUSE mount can stay
 * IS_PENDING indefinitely. A file still being written is handled by the debounce (scan once quiet),
 * the dedupe key (size and time: a finished file is scanned again) and by parsing, since a partial
 * APK does not parse and raises no alert.
 */
@RequiresApi(Build.VERSION_CODES.R)
class MediaStoreDownloadsWatcher(
    private val context: Context,
    private val scope: CoroutineScope,
    private val state: ProtectionStateStore,
    private val onCandidate: (ApkCandidate) -> Unit
) : ApkWatcher {
    private val collection = MediaStore.Files.getContentUri(MediaStore.VOLUME_EXTERNAL)
    private val changes = KeyedDebouncer<Unit, Unit>(scope, QUIET_MILLIS) { _, _ -> collectNew() }
    private val observer =
        object : ContentObserver(Handler(Looper.getMainLooper())) {
            override fun onChange(selfChange: Boolean) {
                scope.launch { changes.submit(Unit, Unit) }
            }
        }

    override fun start() {
        // MediaProvider notifies volume-specific URIs (content://media/external_primary/...), which an
        // observer on .../external/file does not match; the authority root with descendants sees them all.
        // Each wake-up is debounced into one indexed "generation > n" query.
        context.contentResolver.registerContentObserver(MediaStore.AUTHORITY_URI, true, observer)
        scope.launch { collectNew() } // APKs that arrived while protection was not running
    }

    override fun stop() {
        context.contentResolver.unregisterContentObserver(observer)
    }

    private suspend fun collectNew() {
        val version = MediaStore.getVersion(context, MediaStore.VOLUME_EXTERNAL)
        val current = MediaStore.getGeneration(context, MediaStore.VOLUME_EXTERNAL)
        val position = state.mediaStorePosition()
        if (position == null || position.first != version) {
            // First run, or the volume was reset: start from now instead of flagging every old file.
            state.setMediaStorePosition(version, current)
            return
        }
        var newest = position.second
        var found = 0
        query(position.second)?.use { cursor ->
            while (cursor.moveToNext()) {
                found++
                newest = maxOf(newest, cursor.getLong(GENERATION))
                onCandidate(
                    ApkCandidate(
                        displayName = cursor.getString(NAME) ?: "download.apk",
                        path = cursor.getString(DATA),
                        uri = contentUri(cursor),
                        size = cursor.getLong(SIZE),
                        lastModified = cursor.getLong(MODIFIED) * MILLIS_PER_SECOND
                    )
                )
            }
        }
        state.setMediaStorePosition(version, newest)
        Timber.d("MediaStore: %d new APK rows after generation %d", found, position.second)
    }

    /** Without a path (unusual with All files access), read through the provider instead. */
    private fun contentUri(cursor: Cursor): String? =
        if (cursor.isNull(DATA)) ContentUris.withAppendedId(collection, cursor.getLong(ID)).toString() else null

    private fun query(sinceGeneration: Long): Cursor? {
        val selection =
            "${MediaStore.Files.FileColumns.GENERATION_MODIFIED} > ? AND " +
                "${MediaStore.Files.FileColumns.SIZE} > 0 AND " +
                "${MediaStore.Files.FileColumns.RELATIVE_PATH} LIKE ? AND " +
                "(${MediaStore.Files.FileColumns.MIME_TYPE} = ? OR ${MediaStore.Files.FileColumns.DISPLAY_NAME} LIKE ?)"
        val args =
            Bundle().apply {
                putString(ContentResolver.QUERY_ARG_SQL_SELECTION, selection)
                putStringArray(
                    ContentResolver.QUERY_ARG_SQL_SELECTION_ARGS,
                    arrayOf(
                        sinceGeneration.toString(),
                        "${Environment.DIRECTORY_DOWNLOADS}/%",
                        ApkNames.APK_MIME,
                        "%.apk"
                    )
                )
                putString(
                    ContentResolver.QUERY_ARG_SQL_SORT_ORDER,
                    "${MediaStore.Files.FileColumns.GENERATION_MODIFIED} ASC"
                )
                // Queries hide pending rows by default; see the class comment for why they are wanted.
                putInt(MediaStore.QUERY_ARG_MATCH_PENDING, MediaStore.MATCH_INCLUDE)
            }
        return context.contentResolver.query(collection, PROJECTION, args, null)
    }

    private companion object {
        val PROJECTION =
            arrayOf(
                MediaStore.Files.FileColumns._ID,
                MediaStore.Files.FileColumns.DISPLAY_NAME,
                @Suppress("DEPRECATION") MediaStore.Files.FileColumns.DATA,
                MediaStore.Files.FileColumns.SIZE,
                MediaStore.Files.FileColumns.DATE_MODIFIED,
                MediaStore.Files.FileColumns.GENERATION_MODIFIED
            )
        const val ID = 0
        const val NAME = 1
        const val DATA = 2
        const val SIZE = 3
        const val MODIFIED = 4
        const val GENERATION = 5
        const val QUIET_MILLIS = 1_000L
        const val MILLIS_PER_SECOND = 1_000L
    }
}

/**
 * Android 10 and older: inotify on the Downloads directory, which is a real path there.
 * CLOSE_WRITE and MOVED_TO fire once a file is complete. Needs READ_EXTERNAL_STORAGE.
 */
class FileObserverDownloadsWatcher(private val onCandidate: (ApkCandidate) -> Unit) : ApkWatcher {
    @Suppress("DEPRECATION") // the only Downloads path on API <= 29
    private val directory: File = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)

    @Suppress("DEPRECATION") // FileObserver(File) is API 29+; this runs on 26-29
    private val observer =
        object : FileObserver(directory.path, CLOSE_WRITE or MOVED_TO) {
            override fun onEvent(event: Int, path: String?) {
                if (path == null || !ApkNames.isApk(path, null)) return
                val file = File(directory, path)
                onCandidate(
                    ApkCandidate(file.name, path = file.path, size = file.length(), lastModified = file.lastModified())
                )
            }
        }

    override fun start() = observer.startWatching()

    override fun stop() = observer.stopWatching()
}

/**
 * A folder the user picked with the Storage Access Framework (no storage permission needed).
 * The document provider only watches a directory while a cursor on it is open, so one stays open;
 * its notification URI tells us when to re-list. New or changed APKs are reported (top level only).
 */
class SafFolderWatcher(
    private val context: Context,
    private val scope: CoroutineScope,
    private val treeUri: Uri,
    private val onCandidate: (ApkCandidate) -> Unit
) : ApkWatcher {
    private data class Entry(val name: String, val size: Long, val modified: Long, val mime: String?)

    private val children: Uri =
        DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, DocumentsContract.getTreeDocumentId(treeUri))
    private var known: Map<String, Entry> = emptyMap()
    private var open: Cursor? = null
    private var registered: Uri? = null
    private val changes = KeyedDebouncer<Unit, Unit>(scope, QUIET_MILLIS) { _, _ -> relist(report = true) }
    private val observer =
        object : ContentObserver(Handler(Looper.getMainLooper())) {
            override fun onChange(selfChange: Boolean) {
                scope.launch { changes.submit(Unit, Unit) }
            }
        }

    override fun start() {
        relist(report = false)
    }

    override fun stop() {
        context.contentResolver.unregisterContentObserver(observer)
        open?.close()
        open = null
        registered = null
    }

    @Synchronized
    private fun relist(report: Boolean) {
        val cursor =
            try {
                context.contentResolver.query(children, COLUMNS, null, null, null)
            } catch (e: SecurityException) {
                Timber.w(e, "Access to a watched folder was revoked")
                null
            } ?: return
        val now = HashMap<String, Entry>()
        while (cursor.moveToNext()) {
            now[cursor.getString(DOC_ID)] =
                Entry(
                    name = cursor.getString(DOC_NAME) ?: "",
                    size = cursor.getLong(DOC_SIZE),
                    modified = cursor.getLong(DOC_MODIFIED),
                    mime = cursor.getString(DOC_MIME)
                )
        }
        if (report) {
            now.filter { (id, entry) ->
                ApkNames.isApk(entry.name, entry.mime) && known[id] != entry
            }.forEach { (id, entry) ->
                val uri = DocumentsContract.buildDocumentUriUsingTree(treeUri, id)
                onCandidate(
                    ApkCandidate(entry.name, uri = uri.toString(), size = entry.size, lastModified = entry.modified)
                )
            }
        }
        known = now
        // Keep this cursor open (it keeps the provider watching) and observe its notification URI.
        open?.close()
        open = cursor
        // Providers name the URI they notify on; fall back to the children URI if one does not.
        (cursor.notificationUri ?: children).takeIf { it != registered }?.let { uri ->
            context.contentResolver.unregisterContentObserver(observer)
            context.contentResolver.registerContentObserver(uri, true, observer)
            registered = uri
        }
    }

    private companion object {
        const val QUIET_MILLIS = 1_500L
        const val DOC_ID = 0
        const val DOC_NAME = 1
        const val DOC_SIZE = 2
        const val DOC_MODIFIED = 3
        const val DOC_MIME = 4
        val COLUMNS =
            arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_SIZE,
                DocumentsContract.Document.COLUMN_LAST_MODIFIED,
                DocumentsContract.Document.COLUMN_MIME_TYPE
            )
    }
}
