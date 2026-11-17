package com.blackshield.feature.home.onboarding

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.blackshield.feature.home.R
import com.blackshield.testing.ui.Screenshots
import com.blackshield.testing.ui.checkAccessibility
import com.blackshield.testing.ui.setThemedContent
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class OnboardingScreenTest {
    @get:Rule
    val rule = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun walksThroughTheThreeSteps_eachSkippable() {
        var finished = 0
        rule.setThemedContent {
            var step by remember { mutableIntStateOf(0) }
            val next: () -> Unit = {
                if (step < 2) step++ else finished++
            }
            OnboardingScreen(stepIndex = step, onPrimary = next, onSkip = next)
        }

        rule.onNodeWithText(context.getString(R.string.onboarding_welcome_title)).assertIsDisplayed()
        rule.checkAccessibility()
        rule.onNodeWithTag("onboardingPrimary").performClick()
        rule.onNodeWithText(context.getString(R.string.onboarding_protection_title)).assertIsDisplayed()
        rule.checkAccessibility()
        rule.onNodeWithTag("onboardingSkip").performClick()
        rule.onNodeWithText(context.getString(R.string.onboarding_web_title)).assertIsDisplayed()
        rule.checkAccessibility()
        rule.onNodeWithTag("onboardingSkip").performClick()

        assertEquals(1, finished)
    }

    @Test
    fun screenshot_welcome() {
        rule.setThemedContent { OnboardingScreen(stepIndex = 0, onPrimary = {}, onSkip = {}) }
        Screenshots.assertMatchesGolden(rule.onRoot(), "onboarding_welcome")
    }
}
