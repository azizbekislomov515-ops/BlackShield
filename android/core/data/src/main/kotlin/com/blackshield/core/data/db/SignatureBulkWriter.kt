package com.blackshield.core.data.db

import androidx.sqlite.db.SupportSQLiteStatement
import com.blackshield.core.data.model.MalwareSignature
import javax.inject.Inject

/** Writes signature rows; must be called inside a transaction. */
interface SignatureBulkWriter {
    suspend fun upsertAll(signatures: List<MalwareSignature>)
}

/**
 * Bulk upsert with multi-row `INSERT OR REPLACE ... VALUES (...), (...)` statements.
 *
 * Per-statement overhead of the framework SQLite API dominates single-row inserts (~45 us/row on
 * an emulator, the same for Room's generated insert and a raw prepared statement). Binding
 * [ROWS_PER_STATEMENT] rows per execution amortises it: ~3x faster in practice. The statement
 * stays under SQLite's 999-variable limit of older Android versions.
 *
 * Enum columns are written by name, matching Room's built-in enum converter.
 */
internal class MultiRowSignatureWriter
@Inject
constructor(private val database: BlackShieldDatabase) :
    SignatureBulkWriter {
    override suspend fun upsertAll(signatures: List<MalwareSignature>) {
        val rows = signatures
        if (rows.isEmpty()) return
        val db = database.openHelper.writableDatabase
        val fullStatements = rows.size / ROWS_PER_STATEMENT
        if (fullStatements > 0) {
            db.compileStatement(insertSql(ROWS_PER_STATEMENT)).use { statement ->
                for (s in 0 until fullStatements) {
                    statement.bindRows(rows, s * ROWS_PER_STATEMENT, ROWS_PER_STATEMENT)
                    statement.executeInsert()
                }
            }
        }
        val remaining = rows.size % ROWS_PER_STATEMENT
        if (remaining > 0) {
            db.compileStatement(insertSql(remaining)).use { statement ->
                statement.bindRows(rows, rows.size - remaining, remaining)
                statement.executeInsert()
            }
        }
    }

    private fun SupportSQLiteStatement.bindRows(rows: List<MalwareSignature>, from: Int, count: Int) {
        var index = 1
        for (i in from until from + count) {
            val row = rows[i]
            bindString(index++, row.hash)
            bindString(index++, row.algorithm.name)
            bindString(index++, row.family)
            bindString(index++, row.source)
            bindString(index++, row.severity.name)
            bindLong(index++, row.addedAt)
        }
    }

    private fun insertSql(rowCount: Int): String =
        "INSERT OR REPLACE INTO malware_signatures (hash, algorithm, family, source, severity, added_at) VALUES " +
            List(rowCount) { "(?,?,?,?,?,?)" }.joinToString(",")

    internal companion object {
        /** 150 rows x 6 columns = 900 bound variables (limit 999 before SQLite 3.32). */
        const val ROWS_PER_STATEMENT = 150
    }
}
