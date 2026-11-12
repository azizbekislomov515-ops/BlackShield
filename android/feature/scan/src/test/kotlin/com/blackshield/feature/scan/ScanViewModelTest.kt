package com.blackshield.feature.scan

import com.blackshield.core.scanner.ScannerEngine
import org.junit.Assert.assertEquals
import org.junit.Test

class ScanViewModelTest {
    @Test
    fun `exposes the native pong when the engine responds`() {
        val viewModel = ScanViewModel(FakeScannerEngine { "pong" })

        assertEquals(ScanUiState.EngineReady("pong"), viewModel.uiState.value)
    }

    @Test
    fun `reports the failure when the native library cannot be loaded`() {
        val viewModel = ScanViewModel(FakeScannerEngine { throw UnsatisfiedLinkError("no libblackshield_scanner") })

        assertEquals(ScanUiState.EngineUnavailable("no libblackshield_scanner"), viewModel.uiState.value)
    }

    private class FakeScannerEngine(private val onPing: () -> String) : ScannerEngine {
        override fun ping(): String = onPing()
    }
}
