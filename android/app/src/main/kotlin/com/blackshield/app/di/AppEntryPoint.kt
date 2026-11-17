package com.blackshield.app.di

import com.blackshield.core.data.prefs.AppSettingsRepository
import com.blackshield.core.data.quarantine.QuarantineVault
import com.blackshield.core.data.repository.HistoryRepository
import dagger.hilt.EntryPoint
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent

/** App singletons for code Hilt cannot inject into, such as instrumented end-to-end tests. */
@EntryPoint
@InstallIn(SingletonComponent::class)
interface AppEntryPoint {
    fun appSettings(): AppSettingsRepository

    fun quarantineVault(): QuarantineVault

    fun history(): HistoryRepository
}
