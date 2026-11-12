package com.blackshield.core.scanner.di

import com.blackshield.core.scanner.NativeScannerEngine
import com.blackshield.core.scanner.ScannerEngine
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent

@Module
@InstallIn(SingletonComponent::class)
internal abstract class ScannerModule {
    @Binds
    abstract fun bindScannerEngine(impl: NativeScannerEngine): ScannerEngine
}
