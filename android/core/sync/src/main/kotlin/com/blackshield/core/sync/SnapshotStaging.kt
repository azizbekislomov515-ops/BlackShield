package com.blackshield.core.sync

import com.blackshield.core.network.BlackShieldApi
import com.blackshield.core.network.InvalidPayloadException
import com.blackshield.core.network.SnapshotReader
import com.blackshield.core.network.TruncatedSnapshotException
import java.io.EOFException
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import okio.BufferedSource
import okio.buffer
import okio.gzip
import okio.source
import retrofit2.HttpException

/**
 * Downloads the full snapshot to a file before anything touches the database, so the write
 * transaction never waits on the network. The body is stored as received (gzip when the server
 * compressed it) and the file is deleted afterwards, whatever happens.
 *
 * Errors are mapped so the UI can tell them apart: reading the network fails with
 * [IncompleteDownloadException], writing the file with [SyncStorageException]; re-reading the
 * file, an early end is a [TruncatedSnapshotException] and anything else [InvalidPayloadException].
 */
internal class SnapshotStaging(
    private val api: BlackShieldApi,
    private val directory: File,
    private val maxBytes: Long
) {
    class Download(private val file: File, private val gzipped: Boolean) {
        suspend fun <T> read(block: suspend (SnapshotReader) -> T): T = try {
            open().use { source -> block(SnapshotReader(source)) }
        } catch (e: TruncatedSnapshotException) {
            throw e
        } catch (e: EOFException) {
            throw TruncatedSnapshotException(e.message ?: "snapshot ended early", e)
        } catch (e: IOException) {
            throw InvalidPayloadException("damaged snapshot data", e)
        }

        private fun open(): BufferedSource {
            val raw = file.source()
            return (if (gzipped) raw.gzip() else raw).buffer()
        }
    }

    suspend fun <T> withDownload(block: suspend (Download) -> T): T {
        val file = File(directory, FILE_NAME)
        try {
            return block(download(file))
        } finally {
            file.delete()
        }
    }

    private suspend fun download(file: File): Download {
        val response = api.signatureSnapshot()
        val body = response.body()
        if (!response.isSuccessful || body == null) {
            response.errorBody()?.close()
            throw HttpException(response)
        }
        body.use { copyToFile(it.byteStream(), file) }
        return Download(file, gzipped = response.headers()["Content-Encoding"].equals("gzip", ignoreCase = true))
    }

    private suspend fun copyToFile(input: InputStream, file: File) {
        val output = storage {
            directory.mkdirs()
            FileOutputStream(file)
        }
        output.use {
            val buffer = ByteArray(BUFFER_BYTES)
            var total = 0L
            while (true) {
                currentCoroutineContext().ensureActive()
                val read = network { input.read(buffer) }
                if (read == -1) break
                total += read
                if (total > maxBytes) throw InvalidPayloadException("snapshot exceeds the size limit")
                storage { output.write(buffer, 0, read) }
            }
        }
    }

    private inline fun <T> network(block: () -> T): T = try {
        block()
    } catch (e: IOException) {
        throw IncompleteDownloadException(e)
    }

    private inline fun <T> storage(block: () -> T): T = try {
        block()
    } catch (e: IOException) {
        throw SyncStorageException(e)
    }

    private companion object {
        const val FILE_NAME = "snapshot.ndjson.part"
        const val BUFFER_BYTES = 64 * 1024
    }
}
