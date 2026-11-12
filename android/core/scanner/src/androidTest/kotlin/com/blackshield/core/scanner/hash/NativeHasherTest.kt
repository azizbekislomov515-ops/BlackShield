package com.blackshield.core.scanner.hash

import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.File
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Verifies the Kotlin wrapper + JNI bridge on a device against the same vectors as GoogleTest. */
@RunWith(AndroidJUnit4::class)
class NativeHasherTest {
    private val hasher = NativeHasher()
    private val created = mutableListOf<File>()

    @After
    fun cleanUp() {
        created.forEach {
            it.setReadable(true, true)
            it.delete()
        }
    }

    @Test
    fun knownVectors() = runBlocking {
        val million = ByteArray(1_000_000) { 'a'.code.toByte() }
        val vectors: List<Triple<HashAlgorithm, ByteArray, String>> =
            listOf(
                Triple(HashAlgorithm.MD5, "abc".toByteArray(), "900150983cd24fb0d6963f7d28e17f72"),
                Triple(HashAlgorithm.MD5, "message digest".toByteArray(), "f96b697d7cb7938d525a2f31aaf161d0"),
                Triple(HashAlgorithm.MD5, million, "7707d6ae4e027c70eea2a935c2296f21"),
                Triple(HashAlgorithm.SHA1, "abc".toByteArray(), "a9993e364706816aba3e25717850c26c9cd0d89d"),
                Triple(HashAlgorithm.SHA1, ABC_448.toByteArray(), "84983e441c3bd26ebaae4aa1f95129e5e54670f1"),
                Triple(HashAlgorithm.SHA1, million, "34aa973cd4c4daa4f61eeb2bdbad27316534016f"),
                Triple(
                    HashAlgorithm.SHA256,
                    "abc".toByteArray(),
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                ),
                Triple(
                    HashAlgorithm.SHA256,
                    ABC_448.toByteArray(),
                    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
                ),
                Triple(
                    HashAlgorithm.SHA256,
                    million,
                    "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
                )
            )
        vectors.forEachIndexed { i, (algorithm, input, expected) ->
            val file = track(TestFiles.write("vector_$i", input))
            assertEquals(
                "$algorithm #$i",
                HashResult.Success(algorithm, expected, input.size.toLong()),
                hasher.hashFile(file.path, algorithm)
            )
        }
    }

    @Test
    fun emptyAndOneByteFiles() = runBlocking {
        val empty = track(TestFiles.write("empty", ByteArray(0)))
        val one = track(TestFiles.write("one", byteArrayOf('a'.code.toByte())))
        assertEquals(
            HashResult.Success(HashAlgorithm.SHA256, EMPTY_SHA256, 0),
            hasher.hashFile(empty.path)
        )
        assertEquals(
            HashResult.Success(HashAlgorithm.MD5, "0cc175b9c0f1b6a831c399e269772661", 1),
            hasher.hashFile(one.path, HashAlgorithm.MD5)
        )
        assertEquals(
            HashResult.Success(HashAlgorithm.SHA1, "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8", 1),
            hasher.hashFile(one.path, HashAlgorithm.SHA1)
        )
    }

    @Test
    fun over100MiBMatchesMessageDigest() = runBlocking {
        val size = 100 * TestFiles.MIB + 13
        val (file, expected) = TestFiles.writePattern("large.bin", size)
        track(file)
        for (algorithm in HashAlgorithm.entries) {
            assertEquals(
                algorithm.name,
                HashResult.Success(algorithm, expected.getValue(algorithm), size),
                hasher.hashFile(file.path, algorithm)
            )
        }
        // Same digest as the Python reference used by the native suite.
        assertEquals(
            "4036a5fcda813e5adf90a2b38f8999110eb4ada8374db91a36cff56b32a3febd",
            expected[HashAlgorithm.SHA256]
        )
    }

    @Test
    fun parcelFileDescriptorFromStartWithoutMovingOffset() = runBlocking {
        val file = track(TestFiles.write("pfd", "abc".toByteArray()))
        ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY).use { pfd ->
            Os.lseek(pfd.fileDescriptor, 2, OsConstants.SEEK_SET)

            val result = hasher.hashFd(pfd, HashAlgorithm.SHA256)

            assertEquals(HashResult.Success(HashAlgorithm.SHA256, ABC_SHA256, 3), result)
            assertEquals(2L, Os.lseek(pfd.fileDescriptor, 0, OsConstants.SEEK_CUR))
            assertTrue("descriptor stays valid", pfd.fileDescriptor.valid())
        }
    }

    @Test
    fun pipeDescriptor() = runBlocking {
        val (read, write) = ParcelFileDescriptor.createPipe()
        val payload = ByteArray(5 * 65_536 + 3) { (it % 251).toByte() }
        val writer =
            Thread {
                ParcelFileDescriptor.AutoCloseOutputStream(write).use { it.write(payload) }
            }.apply { start() }

        val result = read.use { hasher.hashFd(it, HashAlgorithm.SHA256) }
        writer.join()

        assertEquals(
            HashResult.Success(
                HashAlgorithm.SHA256,
                TestFiles.digest(HashAlgorithm.SHA256, payload),
                payload.size.toLong()
            ),
            result
        )
    }

    @Test
    fun missingFileIsFileNotFound() = runBlocking {
        assertEquals(HashResult.FileNotFound, hasher.hashFile(File(TestFiles.dir, "nope/missing.bin").path))
    }

    @Test
    fun unreadableFileIsPermissionDenied() = runBlocking {
        val file = track(TestFiles.write("unreadable", "secret".toByteArray()))
        assertTrue(file.setReadable(false, false))

        assertEquals(HashResult.PermissionDenied, hasher.hashFile(file.path))
    }

    @Test
    fun invalidInputsDoNotCrash() = runBlocking {
        assertEquals(
            HashResult.Error(HashResult.Error.Reason.INVALID_ARGUMENT, OsConstants.EINVAL),
            hasher.hashFile("")
        )
        assertEquals(
            HashResult.Error(HashResult.Error.Reason.INVALID_ARGUMENT, OsConstants.EINVAL),
            hasher.hashFile("/data/local/tmp/\u0000evil")
        )
        assertEquals(
            HashResult.Error(HashResult.Error.Reason.INVALID_ARGUMENT, OsConstants.EINVAL),
            hasher.hashFile("/data/local/tmp/\uD800lone-surrogate")
        )
        assertEquals(
            HashResult.Error(HashResult.Error.Reason.INVALID_ARGUMENT, OsConstants.EBADF),
            hasher.hashFd(-1, HashAlgorithm.SHA256, null)
        )
        assertEquals(
            HashResult.Error(HashResult.Error.Reason.IO_ERROR, OsConstants.EISDIR),
            hasher.hashFile(TestFiles.dir.path)
        )
    }

    @Test
    fun rawBridgeRejectsBadArguments() {
        val result = LongArray(HashBridge.RESULT_SIZE)
        // Unknown algorithm, unknown (forged) cancel token, undersized result array, null result.
        assertEquals(null, NativeHashBridge.hashFile("/x", 42, HashBridge.NO_CANCEL_TOKEN, result))
        assertEquals(HashBridge.STATUS_INVALID_ARGUMENT, result[HashBridge.RESULT_STATUS])
        assertEquals(null, NativeHashBridge.hashFd(0, HashAlgorithm.SHA256.nativeId, 0x7fff_ffff_0000L, result))
        assertEquals(HashBridge.STATUS_INVALID_ARGUMENT, result[HashBridge.RESULT_STATUS])
        assertEquals(null, NativeHashBridge.hashFile("/x", HashAlgorithm.SHA256.nativeId, 0, LongArray(1)))
        assertEquals(null, NativeHashBridge.hashFile("/nope", HashAlgorithm.SHA256.nativeId, 0, null))
        // Unknown tokens are ignored rather than dereferenced.
        NativeHashBridge.cancel(-5)
        NativeHashBridge.releaseCancelToken(123_456_789)
    }

    @Test
    fun cancellationSignalReturnsCancelled() = runBlocking {
        val signal = CancellationSignal().apply { cancel() }
        val file = track(TestFiles.write("signal", "abc".toByteArray()))

        assertEquals(HashResult.Cancelled, hasher.hashFile(file.path, cancellationSignal = signal))
    }

    private fun track(file: File): File = file.also { created += it }

    private companion object {
        const val ABC_448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        const val ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        const val EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
}
