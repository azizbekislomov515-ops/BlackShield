package com.blackshield.feature.threats.history

import android.content.Context
import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.blackshield.core.data.model.HistoryEvent
import com.blackshield.core.data.model.ScanSource
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.data.repository.HistoryFilter
import com.blackshield.core.data.repository.HistoryPeriod
import com.blackshield.core.data.repository.HistoryRepository
import com.blackshield.feature.threats.R
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.IOException
import java.time.Clock
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class HistoryUiState(
    val filter: HistoryFilter = HistoryFilter(),
    val events: List<HistoryEvent> = emptyList(),
    val now: Long = 0
)

enum class ExportFormat(val mimeType: String, val extension: String) {
    JSON("application/json", "json"),
    PDF("application/pdf", "pdf")
}

@HiltViewModel
class HistoryViewModel
@Inject
constructor(
    @param:ApplicationContext private val context: Context,
    private val history: HistoryRepository,
    private val clock: Clock
) : ViewModel() {
    private val filter = MutableStateFlow(HistoryFilter())
    private val exportResults = Channel<Boolean>(Channel.BUFFERED)

    /** true: the report was saved; false: it could not be written. */
    val exports: Flow<Boolean> = exportResults.receiveAsFlow()

    @OptIn(ExperimentalCoroutinesApi::class)
    val state: StateFlow<HistoryUiState> =
        combine(
            filter,
            filter.flatMapLatest {
                history.observe(it)
            }
        ) { current, events -> HistoryUiState(current, events, clock.millis()) }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MILLIS), HistoryUiState())

    fun setPeriod(period: HistoryPeriod) = filter.update { it.copy(period = period) }

    fun toggleVerdict(verdict: Verdict) = filter.update { it.copy(verdicts = it.verdicts.toggle(verdict)) }

    fun toggleSource(source: ScanSource) = filter.update { it.copy(sources = it.sources.toggle(source)) }

    fun clearFilters() {
        filter.value = HistoryFilter()
    }

    /** Writes the filtered history to [destination] (a document the user created with the file picker). */
    fun export(format: ExportFormat, destination: Uri) {
        val events = state.value.events
        val current = filter.value
        viewModelScope.launch {
            val saved =
                withContext(Dispatchers.IO) {
                    try {
                        context.contentResolver.openOutputStream(destination)?.use { out ->
                            when (format) {
                                ExportFormat.JSON ->
                                    HistoryExport.writeJson(
                                        HistoryExport.report(
                                            context.getString(R.string.report_app),
                                            current,
                                            events,
                                            clock.millis()
                                        ),
                                        out
                                    )

                                ExportFormat.PDF -> HistoryExport.writePdf(
                                    context.resources,
                                    events,
                                    clock.millis(),
                                    out
                                )
                            }
                            true
                        } ?: false
                    } catch (_: IOException) {
                        false
                    } catch (_: SecurityException) {
                        false
                    }
                }
            exportResults.send(saved)
        }
    }

    private fun <T> Set<T>.toggle(value: T): Set<T> = if (value in this) this - value else this + value

    private companion object {
        const val STOP_TIMEOUT_MILLIS = 5_000L
    }
}
