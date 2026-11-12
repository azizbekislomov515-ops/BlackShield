package com.blackshield.feature.scan

import androidx.lifecycle.ViewModel
import com.blackshield.core.scanner.ScannerEngine
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import timber.log.Timber

sealed interface ScanUiState {
    data class EngineReady(val pong: String) : ScanUiState

    data class EngineUnavailable(val reason: String) : ScanUiState
}

@HiltViewModel
class ScanViewModel
@Inject
constructor(scannerEngine: ScannerEngine) : ViewModel() {
    private val _uiState = MutableStateFlow(pingEngine(scannerEngine))
    val uiState: StateFlow<ScanUiState> = _uiState.asStateFlow()

    private fun pingEngine(engine: ScannerEngine): ScanUiState = runCatching { engine.ping() }
        .fold(
            onSuccess = { ScanUiState.EngineReady(it) },
            onFailure = { error ->
                Timber.e(error, "Native scanner ping failed")
                ScanUiState.EngineUnavailable(error.message ?: error::class.java.simpleName)
            }
        )
}
