package com.blackshield.app.di

import android.content.Context
import androidx.work.WorkManager
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent

/**
 * WorkManager is owned by the app: BlackShieldApplication configures it (Hilt worker factory),
 * and feature/core modules (protection, signature sync) inject it from here.
 */
@Module
@InstallIn(SingletonComponent::class)
internal object AppModule {
    @Provides
    fun provideWorkManager(@ApplicationContext context: Context): WorkManager = WorkManager.getInstance(context)
}
