package com.blackshield.core.data.di

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.preferencesDataStoreFile
import androidx.room.withTransaction
import com.blackshield.core.data.db.AllowListDao
import com.blackshield.core.data.db.BlackShieldDatabase
import com.blackshield.core.data.db.MultiRowSignatureWriter
import com.blackshield.core.data.db.QuarantineDao
import com.blackshield.core.data.db.ScanResultDao
import com.blackshield.core.data.db.SignatureBulkWriter
import com.blackshield.core.data.db.SignatureDao
import com.blackshield.core.data.db.SignatureSyncDao
import com.blackshield.core.data.repository.AllowListRepository
import com.blackshield.core.data.repository.OfflineAllowListRepository
import com.blackshield.core.data.repository.OfflineQuarantineRepository
import com.blackshield.core.data.repository.OfflineScanResultRepository
import com.blackshield.core.data.repository.OfflineSignatureRepository
import com.blackshield.core.data.repository.QuarantineRepository
import com.blackshield.core.data.repository.RoomSignatureSyncStore
import com.blackshield.core.data.repository.ScanResultRepository
import com.blackshield.core.data.repository.SignatureRepository
import com.blackshield.core.data.repository.SignatureSyncStore
import com.blackshield.core.data.repository.TransactionRunner
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import java.time.Clock
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
internal object DataModule {
    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): BlackShieldDatabase = BlackShieldDatabase.build(context)

    @Provides
    fun provideSignatureDao(database: BlackShieldDatabase): SignatureDao = database.signatureDao()

    @Provides
    fun provideSignatureSyncDao(database: BlackShieldDatabase): SignatureSyncDao = database.signatureSyncDao()

    @Provides
    fun provideScanResultDao(database: BlackShieldDatabase): ScanResultDao = database.scanResultDao()

    @Provides
    fun provideAllowListDao(database: BlackShieldDatabase): AllowListDao = database.allowListDao()

    @Provides
    fun provideQuarantineDao(database: BlackShieldDatabase): QuarantineDao = database.quarantineDao()

    @Provides
    fun provideTransactionRunner(database: BlackShieldDatabase): TransactionRunner = object : TransactionRunner {
        override suspend fun <R> inTransaction(block: suspend () -> R): R = database.withTransaction { block() }
    }

    @Provides
    @Singleton
    fun provideClock(): Clock = Clock.systemUTC()

    @Provides
    @Singleton
    fun provideUserPreferences(@ApplicationContext context: Context): DataStore<Preferences> =
        PreferenceDataStoreFactory.create(
            produceFile = { context.preferencesDataStoreFile("user_preferences") }
        )
}

@Module
@InstallIn(SingletonComponent::class)
internal abstract class RepositoryModule {
    @Binds
    abstract fun bindSignatureBulkWriter(impl: MultiRowSignatureWriter): SignatureBulkWriter

    @Binds
    @Singleton
    abstract fun bindSignatureRepository(impl: OfflineSignatureRepository): SignatureRepository

    @Binds
    @Singleton
    abstract fun bindSignatureSyncStore(impl: RoomSignatureSyncStore): SignatureSyncStore

    @Binds
    @Singleton
    abstract fun bindScanResultRepository(impl: OfflineScanResultRepository): ScanResultRepository

    @Binds
    @Singleton
    abstract fun bindAllowListRepository(impl: OfflineAllowListRepository): AllowListRepository

    @Binds
    @Singleton
    abstract fun bindQuarantineRepository(impl: OfflineQuarantineRepository): QuarantineRepository
}
