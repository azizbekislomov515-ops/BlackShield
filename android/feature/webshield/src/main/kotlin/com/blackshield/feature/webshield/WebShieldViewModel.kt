package com.blackshield.feature.webshield

import android.content.Intent
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.blackshield.core.data.model.WebActivityEntry
import com.blackshield.core.data.prefs.UserPreferencesRepository
import com.blackshield.core.data.prefs.WebShieldStats
import com.blackshield.core.data.prefs.WebShieldStatsRepository
import com.blackshield.core.data.repository.DomainSyncStore
import com.blackshield.core.data.repository.WebActivityRepository
import com.blackshield.core.data.repository.WebAllowListRepository
import com.blackshield.core.sync.SyncStateRepository
import com.blackshield.core.sync.di.DomainSyncState
import dagger.hilt.android.lifecycle.HiltViewModel
import java.time.Instant
import javax.inject.Inject
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

data class WebShieldUiState(
    val status: WebShieldStatus = WebShieldStatus.Off,
    val enabled: Boolean = false,
    val stats: WebShieldStats = WebShieldStats(),
    val blocklistSize: Long = 0,
    val blocklistUpdatedAt: Instant? = null,
    val allowList: List<String> = emptyList(),
    val notifyBlocked: Boolean = true,
    val activityLog: Boolean = false,
    val activity: List<WebActivityEntry> = emptyList()
)

@HiltViewModel
class WebShieldViewModel
@Inject
constructor(
    private val controller: WebShieldController,
    runtime: WebShieldRuntime,
    private val preferences: UserPreferencesRepository,
    private val statsRepository: WebShieldStatsRepository,
    private val allowListRepository: WebAllowListRepository,
    private val activityRepository: WebActivityRepository,
    store: DomainSyncStore,
    @param:DomainSyncState syncState: SyncStateRepository
) : ViewModel() {
    private class Settings(val enabled: Boolean, val notify: Boolean, val log: Boolean)

    private val settings =
        combine(
            preferences.webShieldEnabled,
            preferences.webShieldNotifyBlocked,
            preferences.webShieldActivityLog,
            ::Settings
        )

    @OptIn(ExperimentalCoroutinesApi::class)
    private val activity = preferences.webShieldActivityLog.flatMapLatest { on ->
        if (on) activityRepository.recent() else flowOf(emptyList())
    }

    private val blocklist =
        combine(store.observeCount(), syncState.state) { count, sync -> count to sync.lastSuccessAt }

    val state: StateFlow<WebShieldUiState> =
        combine(
            runtime.status,
            settings,
            statsRepository.stats,
            blocklist,
            combine(allowListRepository.domains, activity, ::Pair)
        ) {
                status,
                prefs,
                stats,
                list,
                (allowed, recent)
            ->
            WebShieldUiState(
                status = status,
                enabled = prefs.enabled,
                stats = stats,
                blocklistSize = list.first,
                blocklistUpdatedAt = list.second,
                allowList = allowed,
                notifyBlocked = prefs.notify,
                activityLog = prefs.log,
                activity = recent
            )
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MILLIS), WebShieldUiState())

    /** The system's VPN permission dialog, or null when granted. */
    fun consentIntent(): Intent? = controller.consentIntent()

    fun enable() = viewModelScope.launch { controller.enable() }

    fun disable() = viewModelScope.launch { controller.disable() }

    fun setNotifyBlocked(notify: Boolean) = viewModelScope.launch { preferences.setWebShieldNotifyBlocked(notify) }

    fun setActivityLog(enabled: Boolean) = viewModelScope.launch {
        preferences.setWebShieldActivityLog(enabled)
        if (!enabled) activityRepository.clear() // turning the log off deletes it
    }

    fun clearActivity() = viewModelScope.launch { activityRepository.clear() }

    /** Adds [input] to the allowlist; false if it is not a domain. */
    fun allow(input: String): Boolean {
        val domain = AllowListInput.parse(input) ?: return false
        viewModelScope.launch { allowListRepository.allow(domain) }
        return true
    }

    fun removeAllowed(domain: String) = viewModelScope.launch { allowListRepository.remove(domain) }

    private companion object {
        const val STOP_TIMEOUT_MILLIS = 5_000L
    }
}

/** What the user types into the allowlist field: a domain, or a URL to take the host from. */
object AllowListInput {
    private val DOMAIN = Regex("^(?=.{3,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\\.)+[a-z0-9-]{2,63}$")

    fun parse(input: String): String? {
        var value = input.trim().lowercase()
        value = value.substringAfter("://").substringBefore('/').substringBefore('?').substringBefore('#')
        value = value.substringAfterLast('@').substringBefore(':').trimEnd('.')
        return value.takeIf { DOMAIN.matches(it) }
    }
}
