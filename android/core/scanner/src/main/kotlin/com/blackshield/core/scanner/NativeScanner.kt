package com.blackshield.core.scanner

import javax.inject.Inject
import javax.inject.Singleton

/** JNI bindings for `libblackshield_scanner.so`. */
internal object NativeScanner {
    init {
        System.loadLibrary("blackshield_scanner")
    }

    // Must stay public: Kotlin mangles internal member names, which would break the JNI symbol lookup.
    external fun nativePing(): String
}

@Singleton
internal class NativeScannerEngine
@Inject
constructor() : ScannerEngine {
    override fun ping(): String = NativeScanner.nativePing()
}
