package com.blackshield.feature.protection

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import com.blackshield.core.data.prefs.UserPreferencesRepository
import com.blackshield.core.data.repository.ScanResultRepository
import com.blackshield.core.data.repository.SignatureRepository
import dagger.hilt.EntryPoint
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.StateFlow
import timber.log.Timber

/**
 * Starts and stops [RealtimeProtectionService]. Starting is only allowed while the app is in the
 * foreground or from an exempt broadcast (boot, app update); see [start].
 */
@Singleton
class ProtectionController
@Inject
constructor(
    @param:ApplicationContext private val context: Context,
    private val preferences: UserPreferencesRepository
) {
    val isRunning: StateFlow<Boolean> = RealtimeProtectionService.isRunning

    /**
     * Starts the service. Android 12+ refuses foreground-service starts from the background
     * (ForegroundServiceStartNotAllowedException) except from exempt contexts; such a refusal is
     * logged, not thrown. The troubleshooting screen reports a service that is not running.
     */
    fun start(): Boolean = try {
        ContextCompat.startForegroundService(context, Intent(context, RealtimeProtectionService::class.java))
        true
    } catch (e: IllegalStateException) {
        Timber.w(e, "Could not start real-time protection (background start not allowed)")
        false
    }

    fun stop() {
        context.stopService(Intent(context, RealtimeProtectionService::class.java))
    }

    /** Re-reads storage grants and watched folders; a no-op when the service is not running. */
    fun refresh() {
        if (!isRunning.value) return
        runCatching {
            context.startService(
                Intent(
                    context,
                    RealtimeProtectionService::class.java
                ).setAction(RealtimeProtectionService.ACTION_REFRESH)
            )
        }.onFailure { Timber.w(it, "Could not refresh real-time protection") }
    }

    suspend fun setEnabled(enabled: Boolean) {
        preferences.setRealTimeProtectionEnabled(enabled)
        if (enabled) start() else stop()
    }
}

/** For components Hilt cannot inject (receivers) and for instrumented tests. */
@EntryPoint
@InstallIn(SingletonComponent::class)
interface ProtectionEntryPoint {
    fun preferences(): UserPreferencesRepository

    fun controller(): ProtectionController

    fun state(): ProtectionStateStore

    fun notifications(): ProtectionNotifications

    fun scanResults(): ScanResultRepository

    fun signatures(): SignatureRepository
}
