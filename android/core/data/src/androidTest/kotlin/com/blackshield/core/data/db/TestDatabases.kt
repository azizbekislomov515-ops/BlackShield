package com.blackshield.core.data.db

import android.content.Context
import androidx.room.withTransaction
import androidx.test.platform.app.InstrumentationRegistry
import com.blackshield.core.data.repository.TransactionRunner

internal object TestDatabases {
    val context: Context get() = InstrumentationRegistry.getInstrumentation().targetContext

    /** File-backed database built exactly like production (migrations included). */
    fun open(name: String): BlackShieldDatabase = BlackShieldDatabase.build(context, name)

    fun delete(name: String) {
        context.deleteDatabase(name)
    }

    fun transactions(db: BlackShieldDatabase): TransactionRunner = object : TransactionRunner {
        override suspend fun <R> inTransaction(block: suspend () -> R): R = db.withTransaction { block() }
    }
}
