package com.blackshield.feature.settings

import androidx.compose.foundation.layout.Column
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertIsOff
import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.blackshield.core.data.prefs.ScanFrequency
import com.blackshield.core.data.prefs.ScanSchedule
import com.blackshield.core.data.prefs.ThemeMode
import com.blackshield.testing.ui.Screenshots
import com.blackshield.testing.ui.checkAccessibility
import com.blackshield.testing.ui.setThemedContent
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ScheduleSectionTest {
    @get:Rule
    val rule = createComposeRule()

    private var schedule by mutableStateOf(ScanSchedule())
    private var theme by mutableStateOf(ThemeMode.SYSTEM)

    private fun show() {
        rule.setThemedContent {
            Column {
                ScheduleSection(schedule) { schedule = it }
                AppearanceSection(theme) { theme = it }
            }
        }
    }

    @Test
    fun frequencyAndConditions_areSavedAsTheUserPicksThem() {
        show()
        rule.onNodeWithTag("frequency_WEEKLY").assertIsSelected()
        rule.onNodeWithTag("scheduleCharging").assertIsOn()
        rule.checkAccessibility()

        rule.onNodeWithTag("frequency_DAILY").performClick()
        rule.onNodeWithTag("scheduleCharging").performClick().assertIsOff()
        rule.onNodeWithTag("scheduleIdle").performClick().assertIsOn()

        assertEquals(ScanSchedule(ScanFrequency.DAILY, requiresCharging = false, requiresIdle = true), schedule)
    }

    @Test
    fun turningTheScheduleOff_disablesItsConditions() {
        show()

        rule.onNodeWithTag("frequency_OFF").performClick()

        rule.onNodeWithTag("scheduleCharging").assertIsNotEnabled()
        rule.onNodeWithTag("scheduleIdle").assertIsNotEnabled()
    }

    @Test
    fun theme_canBeForcedDarkOrLight() {
        show()

        rule.onNodeWithTag("theme_DARK").performClick().assertIsSelected()

        assertEquals(ThemeMode.DARK, theme)
    }

    @Test
    fun screenshot() {
        show()
        Screenshots.assertMatchesGolden(rule.onRoot(), "settings_schedule")
    }
}
