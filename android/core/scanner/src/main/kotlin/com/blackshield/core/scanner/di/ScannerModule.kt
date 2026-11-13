package com.blackshield.core.scanner.di

import android.content.Context
import android.os.Process
import com.blackshield.core.scanner.BuildConfig
import com.blackshield.core.scanner.NativeScannerEngine
import com.blackshield.core.scanner.ScannerEngine
import com.blackshield.core.scanner.analysis.ApkAnalyzer
import com.blackshield.core.scanner.analysis.PackageManagerApkAnalyzer
import com.blackshield.core.scanner.apps.InstalledAppSource
import com.blackshield.core.scanner.apps.PackageManagerAppSource
import com.blackshield.core.scanner.hash.FileHasher
import com.blackshield.core.scanner.hash.NativeHasher
import com.blackshield.core.scanner.risk.BundledRiskRulesSource
import com.blackshield.core.scanner.risk.RiskRulesSource
import com.blackshield.core.scanner.yara.ApkPatternScanner
import com.blackshield.core.scanner.yara.RulesetVerifier
import com.blackshield.core.scanner.yara.YaraApkScanner
import com.blackshield.core.scanner.yara.YaraRules
import com.blackshield.core.scanner.yara.YaraRulesInstaller
import com.blackshield.core.scanner.yara.YaraScanner
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import java.io.File
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

    @Binds
    abstract fun bindApkAnalyzer(impl: PackageManagerApkAnalyzer): ApkAnalyzer

    @Binds
    abstract fun bindRiskRulesSource(impl: BundledRiskRulesSource): RiskRulesSource

    @Binds
    abstract fun bindApkPatternScanner(impl: YaraApkScanner): ApkPatternScanner

    @Binds
    abstract fun bindYaraRulesInstaller(impl: YaraRules): YaraRulesInstaller

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

        /** Bundled rules from assets, signed updates in no-backup storage (never restored onto another device). */
        @Provides
        @Singleton
        fun provideYaraRules(@ApplicationContext context: Context): YaraRules = YaraRules(
            directory = File(context.noBackupFilesDir, "yara"),
            bundledSource = { context.assets.open("yara/bundled.yar").bufferedReader().use { it.readText() } },
            verifier = RulesetVerifier(RulesetVerifier.parseKeys(BuildConfig.YARA_RULES_PUBLIC_KEYS)),
            compiler = { source -> YaraScanner.compile(source) }
        )

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
