package com.blackshield.core.data.quarantine

import android.content.Context
import android.provider.DocumentsContract
import androidx.core.net.toUri
import com.blackshield.core.data.db.FileThreatDao
import com.blackshield.core.data.model.FileThreat
import com.blackshield.core.data.model.FileThreatState
import com.blackshield.core.data.model.HistoryEvent
import com.blackshield.core.data.model.HistoryKind
import com.blackshield.core.data.model.ScanSource
import com.blackshield.core.data.repository.HistoryRepository
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.time.Clock
import java.util.UUID
import javax.inject.Inject
import javax.inject.Provider
import javax.inject.Singleton
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import timber.log.Timber

sealed interface QuarantineOutcome {
    /** Encrypted into the vault and the original removed. */
    data object Quarantined : QuarantineOutcome

    /** Encrypted into the vault, but the original could not be deleted: the user must delete it. */
    data object OriginalKept : QuarantineOutcome

    /** Nothing changed (the file is gone or unreadable). */
    data object Failed : QuarantineOutcome
}

/**
 * Harmful APK files: detections waiting for a decision, and the quarantine vault.
 *
 * Quarantining streams the file through [VaultCipher] into app-private, no-backup storage, then
 * deletes the original. The encrypted copy cannot be installed or opened by anything; it can only
 * be restored by the user (to a location they pick) or deleted for good. Every action is recorded
 * in the history.
 */
@Singleton
class QuarantineVault
@Inject
constructor(
    @param:ApplicationContext private val context: Context,
    private val dao: FileThreatDao,
    private val history: HistoryRepository,
    private val cipher: Provider<VaultCipher>,
    private val clock: Clock
) {
    private val directory: File get() = File(context.noBackupFilesDir, VAULT_DIRECTORY).apply { mkdirs() }
    private val sources = SourceFiles(context)

    fun detected(): Flow<List<FileThreat>> = dao.observe(FileThreatState.DETECTED)

    fun quarantined(): Flow<List<FileThreat>> = dao.observe(FileThreatState.QUARANTINED)

    /** Records a harmful file found by a scan; the same unhandled file is recorded once. Returns its id. */
    suspend fun recordDetection(threat: FileThreat): Long =
        dao.findDetected(threat.sourcePath, threat.sourceUri, threat.sha256)?.id ?: dao.insert(threat.copy(id = 0))

    /** "Ignore": forget a detection without touching the file. */
    suspend fun dismiss(id: Long) = dao.delete(id)

    suspend fun quarantine(id: Long): QuarantineOutcome = withContext(Dispatchers.IO) {
        val threat =
            dao.find(id)?.takeIf { it.state == FileThreatState.DETECTED } ?: return@withContext QuarantineOutcome.Failed
        val name = "${UUID.randomUUID()}$VAULT_SUFFIX"
        val target = File(directory, name)
        val encrypted =
            try {
                sources.open(threat).use { input ->
                    target.outputStream().use { cipher.get().encrypt(input, it, aad(name)) }
                }
                true
            } catch (e: IOException) {
                Timber.w(e, "Could not quarantine a file")
                false
            } catch (e: SecurityException) {
                Timber.w(e, "Could not quarantine a file")
                false
            }
        if (!encrypted) {
            target.delete()
            return@withContext QuarantineOutcome.Failed
        }
        val removed = sources.delete(threat)
        dao.update(threat.copy(state = FileThreatState.QUARANTINED, vaultFile = name, quarantinedAt = clock.millis()))
        history.record(event(threat, HistoryKind.QUARANTINED))
        if (removed) QuarantineOutcome.Quarantined else QuarantineOutcome.OriginalKept
    }

    /** Decrypts the file into [destination] (a location the user picked) and removes it from the vault. */
    suspend fun restore(id: Long, destination: OutputStream): Boolean = withContext(Dispatchers.IO) {
        val threat = dao.find(id)?.takeIf { it.state == FileThreatState.QUARANTINED } ?: return@withContext false
        val file = vaultFile(threat) ?: return@withContext false
        val restored =
            try {
                file.inputStream().use { encrypted ->
                    cipher.get().decrypt(encrypted, aad(file.name)).use { it.copyTo(destination) }
                }
                destination.flush()
                true
            } catch (e: IOException) {
                Timber.w(e, "Could not restore a quarantined file") // includes failed authentication
                false
            }
        if (restored) {
            file.delete()
            dao.delete(threat.id)
            history.record(event(threat, HistoryKind.RESTORED))
        }
        restored
    }

    /** Deletes the encrypted copy for good. */
    suspend fun delete(id: Long) = withContext(Dispatchers.IO) {
        val threat = dao.find(id) ?: return@withContext
        vaultFile(threat)?.delete()
        dao.delete(threat.id)
        history.record(event(threat, HistoryKind.DELETED))
    }

    private fun vaultFile(threat: FileThreat): File? = threat.vaultFile?.let {
        File(directory, it)
    }?.takeIf { it.isFile }

    private fun event(threat: FileThreat, kind: HistoryKind) = HistoryEvent(
        occurredAt = clock.millis(),
        kind = kind,
        source = ScanSource.FILE,
        verdict = threat.verdict,
        subject = threat.appLabel ?: threat.displayName,
        target = threat.displayName,
        riskScore = threat.riskScore
    )

    companion object {
        const val VAULT_DIRECTORY = "quarantine"
        private const val VAULT_SUFFIX = ".bsq"

        /** Binds each ciphertext to its own vault entry. */
        fun aad(vaultName: String): ByteArray = "blackshield-quarantine:$vaultName".toByteArray(Charsets.UTF_8)
    }
}

/** The original file of a threat: a path or a content:// URI. */
internal class SourceFiles(private val context: Context) {
    fun open(threat: FileThreat): InputStream = when {
        threat.sourcePath != null -> File(threat.sourcePath).inputStream()

        threat.sourceUri != null -> context.contentResolver.openInputStream(threat.sourceUri.toUri())
            ?: throw FileNotFoundException()

        else -> throw FileNotFoundException()
    }

    /** True if the original is gone. */
    fun delete(threat: FileThreat): Boolean = try {
        when {
            threat.sourcePath != null -> File(threat.sourcePath).let { it.delete() || !it.exists() }
            threat.sourceUri != null -> deleteUri(threat.sourceUri)
            else -> false
        }
    } catch (e: SecurityException) {
        Timber.w(e, "Could not delete the original file")
        false
    }

    private fun deleteUri(uri: String): Boolean {
        val parsed = uri.toUri()
        val document =
            runCatching {
                DocumentsContract.isDocumentUri(context, parsed) &&
                    DocumentsContract.deleteDocument(context.contentResolver, parsed)
            }
                .getOrDefault(false)
        return document || runCatching { context.contentResolver.delete(parsed, null, null) > 0 }.getOrDefault(false)
    }
}
