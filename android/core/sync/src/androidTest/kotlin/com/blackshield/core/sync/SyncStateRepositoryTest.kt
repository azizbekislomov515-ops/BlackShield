package com.blackshield.core.sync

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.time.Instant
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith

/** The production DataStore file, including recovery from a corrupted file. */
@RunWith(AndroidJUnit4::class)
class SyncStateRepositoryTest {
    private val directory = File(InstrumentationRegistry.getInstrumentation().targetContext.cacheDir, "sync-state-test")

    @Test
    fun corruptedFileReadsAsNeverSyncedAndCanBeWrittenAgain() = runTest {
        val file = freshFile("corrupt.preferences_pb")
        file.writeBytes(byteArrayOf(0x7f, 0x13, 0x00, 0x55, 0x01))
        val repository = SyncStateRepository(SyncStateRepository.createDataStore(file))

        assertEquals(SyncState(), repository.current())

        repository.setVersion(3)
        assertEquals(3L, repository.current().version)
    }

    @Test
    fun recordsSuccessAndFailure() = runTest {
        val repository = SyncStateRepository(SyncStateRepository.createDataStore(freshFile("state.preferences_pb")))
        val t1 = Instant.ofEpochMilli(1_000)
        val t2 = Instant.ofEpochMilli(2_000)

        repository.setVersion(7)
        repository.recordFailure(SyncErrorKind.NETWORK, t1)
        assertEquals(
            SyncState(version = 7, lastAttemptAt = t1, lastError = SyncErrorKind.NETWORK),
            repository.current()
        )

        repository.recordSuccess(t2)
        val state = repository.current()
        assertEquals(t2, state.lastSuccessAt)
        assertEquals(t2, state.lastAttemptAt)
        assertNull(state.lastError)
    }

    private fun freshFile(name: String): File {
        directory.mkdirs()
        return File(directory, name).also { it.delete() }
    }
}
