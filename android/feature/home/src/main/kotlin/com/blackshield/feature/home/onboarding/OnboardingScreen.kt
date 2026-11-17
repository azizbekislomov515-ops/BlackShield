package com.blackshield.feature.home.onboarding

import android.Manifest
import android.app.Activity
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import com.blackshield.core.designsystem.R as DsR
import com.blackshield.core.designsystem.component.IconTile
import com.blackshield.core.designsystem.component.PrimaryActionButton
import com.blackshield.core.designsystem.theme.BsTheme
import com.blackshield.feature.home.R

private enum class Step { WELCOME, PROTECTION, WEB_SHIELD }

/** First launch: what BlackShield does, then the two permissions that matter, each skippable. */
@Composable
fun OnboardingRoute(onDone: () -> Unit, viewModel: OnboardingViewModel = hiltViewModel()) {
    var stepIndex by rememberSaveable { mutableIntStateOf(0) }
    val step = Step.entries[stepIndex]
    val next: () -> Unit = {
        if (stepIndex < Step.entries.lastIndex) stepIndex++ else viewModel.finish(onDone)
    }
    val notifications =
        rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
            viewModel.enableProtection()
            next()
        }
    val vpnConsent =
        rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) viewModel.enableWebShield()
            next()
        }
    OnboardingScreen(
        stepIndex = stepIndex,
        onPrimary = {
            when (step) {
                Step.WELCOME -> next()

                Step.PROTECTION ->
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
                    } else {
                        viewModel.enableProtection()
                        next()
                    }

                Step.WEB_SHIELD -> {
                    val consent = viewModel.webShieldConsent()
                    if (consent != null) {
                        vpnConsent.launch(consent)
                    } else {
                        viewModel.enableWebShield()
                        next()
                    }
                }
            }
        },
        onSkip = next
    )
}

@Composable
fun OnboardingScreen(stepIndex: Int, onPrimary: () -> Unit, onSkip: () -> Unit, modifier: Modifier = Modifier) {
    val step = Step.entries[stepIndex]
    val (icon, title, body) =
        when (step) {
            Step.WELCOME -> Triple(
                DsR.drawable.bs_ic_shield_check,
                R.string.onboarding_welcome_title,
                R.string.onboarding_welcome_body
            )

            Step.PROTECTION -> Triple(
                DsR.drawable.bs_ic_bolt,
                R.string.onboarding_protection_title,
                R.string.onboarding_protection_body
            )

            Step.WEB_SHIELD -> Triple(
                DsR.drawable.bs_ic_globe,
                R.string.onboarding_web_title,
                R.string.onboarding_web_body
            )
        }
    val primary =
        when (step) {
            Step.WELCOME -> R.string.onboarding_start
            Step.PROTECTION -> R.string.onboarding_turn_on
            Step.WEB_SHIELD -> R.string.onboarding_turn_on
        }
    Surface(modifier = modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(Modifier.fillMaxSize().safeDrawingPadding().padding(24.dp).testTag("onboarding")) {
            Column(
                Modifier.weight(1f).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                IconTile(icon, BsTheme.status.safe, size = 112.dp)
                Spacer(Modifier.size(32.dp))
                Text(
                    stringResource(title),
                    style = MaterialTheme.typography.headlineMedium,
                    modifier = Modifier.semantics {
                        heading()
                    }
                )
                Spacer(Modifier.size(12.dp))
                Text(
                    stringResource(body),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                if (step == Step.WELCOME) {
                    Spacer(Modifier.size(20.dp))
                    listOf(
                        R.string.onboarding_point_apps,
                        R.string.onboarding_point_files,
                        R.string.onboarding_point_web,
                        R.string.onboarding_point_private
                    )
                        .forEach { Bullet(stringResource(it)) }
                }
            }
            StepDots(stepIndex)
            PrimaryActionButton(
                stringResource(primary),
                onClick = onPrimary,
                modifier = Modifier.padding(top = 16.dp).testTag("onboardingPrimary")
            )
            if (step != Step.WELCOME) {
                TextButton(
                    onClick = onSkip,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("onboardingSkip")
                ) {
                    Text(stringResource(R.string.onboarding_skip))
                }
            }
        }
    }
}

@Composable
private fun Bullet(text: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(8.dp).clip(CircleShape).background(BsTheme.status.safe))
        Spacer(Modifier.width(12.dp))
        Text(text, style = MaterialTheme.typography.bodyLarge)
    }
}

@Composable
private fun StepDots(current: Int) {
    val description = stringResource(R.string.onboarding_step, current + 1, Step.entries.size)
    Row(
        Modifier.fillMaxWidth().semantics(mergeDescendants = true) { contentDescription = description },
        horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally)
    ) {
        Step.entries.indices.forEach { index ->
            Box(
                Modifier
                    .size(width = if (index == current) 24.dp else 8.dp, height = 8.dp)
                    .clip(CircleShape)
                    .background(
                        if (index ==
                            current
                        ) {
                            MaterialTheme.colorScheme.primary
                        } else {
                            MaterialTheme.colorScheme.surfaceContainerHighest
                        }
                    )
            )
        }
    }
}
