package com.blackshield.app

import android.app.Application
import androidx.hilt.work.HiltWorkerFactory
import androidx.work.Configuration
import com.blackshield.app.crash.CrashReports
import com.blackshield.app.crash.CrashUploadWorker
import com.blackshield.app.seed.SignatureSeeder
import com.blackshield.core.data.prefs.AppSettingsRepository
import com.blackshield.core.sync.SignatureSyncScheduler
import com.blackshield.feature.scan.schedule.ScanScheduler
import dagger.hilt.android.HiltAndroidApp
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import timber.log.Timber

@HiltAndroidApp
class BlackShieldApplication :
    Application(),
    Configuration.Provider {
    @Inject
    lateinit var workerFactory: HiltWorkerFactory

    @Inject
    lateinit var signatureSeeder: SignatureSeeder

    @Inject
    lateinit var signatureSyncScheduler: SignatureSyncScheduler

    @Inject
    lateinit var scanScheduler: ScanScheduler

    @Inject
    lateinit var appSettings: AppSettingsRepository

    /** Process-lifetime scope for fire-and-forget startup work. */
    private val applicationScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder().setWorkerFactory(workerFactory).build()

    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) {
            Timber.plant(Timber.DebugTree())
        }
        CrashReports.install(this)
        // Crash reports follow the setting: on sends what is pending, off deletes it (nothing is kept unasked).
        applicationScope.launch {
            appSettings.crashReportsEnabled.collect { enabled ->
                CrashReports.enabled = enabled
                if (enabled) {
                    CrashUploadWorker.enqueue(
                        this@BlackShieldApplication
                    )
                } else {
                    CrashReports.deleteAll(this@BlackShieldApplication)
                }
            }
        }
        applicationScope.launch {
            runCatching { signatureSeeder.seed() }.onFailure { Timber.e(it, "Signature seeding failed") }
        }
        // First-launch sync (expedited) and the periodic schedule, kept in line with the Wi-Fi-only setting.
        applicationScope.launch { signatureSyncScheduler.run() }
        // The scheduled full scan, kept in line with the user's schedule.
        applicationScope.launch { scanScheduler.run() }
    }
}
