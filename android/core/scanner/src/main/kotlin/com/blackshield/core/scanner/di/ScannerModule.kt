package com.blackshield.core.scanner.di

import android.os.Process
import com.blackshield.core.scanner.NativeScannerEngine
import com.blackshield.core.scanner.ScannerEngine
import com.blackshield.core.scanner.apps.InstalledAppSource
import com.blackshield.core.scanner.apps.PackageManagerAppSource
import com.blackshield.core.scanner.hash.FileHasher
import com.blackshield.core.scanner.hash.NativeHasher
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import java.util.concurrent.Executors
import java.util.concurrent.ThreadFactory
import java.util.concurrent.atomic.AtomicInteger
import javax.inject.Qualifier
import javax.inject.Singleton
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.asCoroutineDispatcher

/** Bounded, background-priority dispatcher for scan workers and their native hashing. */
@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class ScanDispatcher

/** Number of apps scanned concurrently. */
@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class ScanParallelism

@Module
@InstallIn(SingletonComponent::class)
internal abstract class ScannerModule {
    @Binds
    abstract fun bindScannerEngine(impl: NativeScannerEngine): ScannerEngine

    @Binds
    abstract fun bindInstalledAppSource(impl: PackageManagerAppSource): InstalledAppSource

    companion object {
        /** Hashing is CPU-bound; leave cores free for the UI thread and the rest of the system. */
        private val PARALLELISM = (Runtime.getRuntime().availableProcessors() / 2).coerceIn(1, 4)

        @Provides
        @ScanParallelism
        fun provideScanParallelism(): Int = PARALLELISM

        /**
         * A fixed pool of [PARALLELISM] threads at THREAD_PRIORITY_BACKGROUND: the scheduler
         * always prefers the UI and render threads, so a scan cannot make the app janky.
         */
        @Provides
        @Singleton
        @ScanDispatcher
        fun provideScanDispatcher(): CoroutineDispatcher = Executors.newFixedThreadPool(
            PARALLELISM,
            BackgroundThreadFactory("blackshield-scan")
        ).asCoroutineDispatcher()

        /** Scanning hashes on the background-priority pool, never on the shared IO pool. */
        @Provides
        @Singleton
        fun provideFileHasher(@ScanDispatcher dispatcher: CoroutineDispatcher): FileHasher = NativeHasher(dispatcher)
    }
}

private class BackgroundThreadFactory(private val prefix: String) : ThreadFactory {
    private val count = AtomicInteger()

    override fun newThread(runnable: Runnable): Thread = Thread(
        {
            Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND)
            runnable.run()
        },
        "$prefix-${count.incrementAndGet()}"
    ).apply { isDaemon = true }
}
