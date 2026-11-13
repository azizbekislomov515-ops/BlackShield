package com.blackshield.app

import android.app.Application
import androidx.hilt.work.HiltWorkerFactory
import androidx.work.Configuration
import com.blackshield.app.seed.SignatureSeeder
import com.blackshield.core.sync.SignatureSyncScheduler
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

    /** Process-lifetime scope for fire-and-forget startup work. */
    private val applicationScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder().setWorkerFactory(workerFactory).build()

    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) {
            Timber.plant(Timber.DebugTree())
        }
        applicationScope.launch {
            runCatching { signatureSeeder.seed() }.onFailure { Timber.e(it, "Signature seeding failed") }
        }
        // First-launch sync (expedited) and the periodic schedule, kept in line with the Wi-Fi-only setting.
        applicationScope.launch { signatureSyncScheduler.run() }
    }
}
