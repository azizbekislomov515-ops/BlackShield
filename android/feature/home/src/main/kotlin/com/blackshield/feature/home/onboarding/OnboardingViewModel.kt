package com.blackshield.feature.home.onboarding

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.blackshield.core.data.prefs.AppSettingsRepository
import com.blackshield.feature.protection.ProtectionController
import com.blackshield.feature.webshield.WebShieldController
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.launch

@HiltViewModel
class OnboardingViewModel
@Inject
constructor(
    private val settings: AppSettingsRepository,
    private val protection: ProtectionController,
    private val webShield: WebShieldController
) : ViewModel() {
    fun enableProtection() = viewModelScope.launch { protection.setEnabled(true) }

    fun webShieldConsent() = webShield.consentIntent()

    fun enableWebShield() = viewModelScope.launch { webShield.enable() }

    fun finish(onDone: () -> Unit) = viewModelScope.launch {
        settings.setOnboardingCompleted()
        onDone()
    }
}
