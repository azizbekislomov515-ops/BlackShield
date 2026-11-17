package com.blackshield.testing.ui

import android.os.Build
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.test.junit4.ComposeContentTestRule
import androidx.compose.ui.test.junit4.ComposeTestRule
import androidx.compose.ui.test.junit4.accessibility.enableAccessibilityChecks
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.tryPerformAccessibilityChecks
import com.blackshield.core.designsystem.theme.BlackShieldTheme

/**
 * Shows [content] in the app theme with Accessibility Test Framework checks on: every action the test performs, and
 * [checkAccessibility], fail on missing labels, small touch targets, low contrast and similar problems.
 */
fun ComposeContentTestRule.setThemedContent(darkTheme: Boolean = true, content: @Composable () -> Unit) {
    enableAccessibilityChecksWhereSupported()
    setContent {
        BlackShieldTheme(darkTheme = darkTheme) {
            Surface(color = MaterialTheme.colorScheme.background) { content() }
        }
    }
}

/** Turns on the checks for the rest of the test. Compose supports them on Android 14 (API 34) and newer. */
fun ComposeTestRule.enableAccessibilityChecksWhereSupported() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) enableAccessibilityChecks()
}

/** Runs the accessibility checks on the whole screen as it is now (Android 14 and newer). */
fun ComposeTestRule.checkAccessibility() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) onRoot().tryPerformAccessibilityChecks()
}
