package com.blackshield.core.sync.di

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.preferencesDataStoreFile
import com.blackshield.core.sync.SyncConfig
import com.blackshield.core.sync.SyncStateRepository
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import java.io.File
import javax.inject.Qualifier
import javax.inject.Singleton

/** The DataStore holding [SyncStateRepository]'s state. */
@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class SyncStateStore

/** Where snapshot downloads are staged before they are applied. */
@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class SyncWorkDirectory

@Module
@InstallIn(SingletonComponent::class)
internal object SyncModule {
    @Provides
    @Singleton
    @SyncStateStore
    fun provideSyncStateDataStore(@ApplicationContext context: Context): DataStore<Preferences> =
        SyncStateRepository.createDataStore(context.preferencesDataStoreFile("signature_sync"))

    /** noBackupFilesDir: not wiped by the system under storage pressure like the cache, never backed up. */
    @Provides
    @SyncWorkDirectory
    fun provideSyncWorkDirectory(@ApplicationContext context: Context): File =
        File(context.noBackupFilesDir, "signature-sync")

    @Provides
    fun provideSyncConfig(): SyncConfig = SyncConfig()
}
