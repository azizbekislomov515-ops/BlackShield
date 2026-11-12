package com.blackshield.core.data.db

import androidx.room.testing.MigrationTestHelper
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.blackshield.core.data.model.Verdict
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MigrationTest {
    @get:Rule
    val helper = MigrationTestHelper(InstrumentationRegistry.getInstrumentation(), BlackShieldDatabase::class.java)

    @After
    fun cleanUp() = TestDatabases.delete(DB)

    @Test
    fun migrate1To2_schemaMatchesExportedV2() {
        helper.createDatabase(DB, 1).close()

        // Validates every table, column, index and primary key against schemas/.../2.json.
        helper.runMigrationsAndValidate(DB, 2, true, MIGRATION_1_2).close()
    }

    @Test
    fun migrate1To2_keepsLatestV1ResultPerTarget() {
        helper.createDatabase(DB, 1).apply {
            execSQL("INSERT INTO scan_results (target, verdict, scannedAtEpochMillis) VALUES ('com.a', 'CLEAN', 100)")
            execSQL(
                "INSERT INTO scan_results (target, verdict, scannedAtEpochMillis) VALUES ('com.a', 'MALICIOUS', 200)"
            )
            execSQL("INSERT INTO scan_results (target, verdict, scannedAtEpochMillis) VALUES ('com.b', 'weird', 300)")
            close()
        }
        helper.runMigrationsAndValidate(DB, 2, true, MIGRATION_1_2).close()

        val db = TestDatabases.open(DB)
        val results = runBlocking { db.scanResultDao().observeAll().first() }.associateBy { it.packageName }
        db.close()

        assertEquals(setOf("com.a", "com.b"), results.keys)
        assertEquals(Verdict.MALICIOUS, results.getValue("com.a").verdict)
        assertEquals(200L, results.getValue("com.a").scannedAt)
        assertEquals("unknown v1 verdicts fall back to CLEAN", Verdict.CLEAN, results.getValue("com.b").verdict)
        assertEquals(emptyList<Any>(), results.getValue("com.b").reasons)
        assertNull(results.getValue("com.b").apkSha256)
    }

    @Test
    fun freshInstallAndMigratedDatabaseAreUsable() {
        helper.createDatabase(DB, 1).close()
        val db = TestDatabases.open(DB) // Room runs MIGRATION_1_2 and validates on open
        runBlocking {
            assertEquals(0L, db.signatureDao().count())
            assertEquals(emptyList<String>(), db.allowListDao().packageNames())
        }
        db.close()
    }

    private companion object {
        const val DB = "migration-test.db"
    }
}
