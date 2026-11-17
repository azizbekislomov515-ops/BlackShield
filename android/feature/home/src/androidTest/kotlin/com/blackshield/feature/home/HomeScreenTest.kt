package com.blackshield.feature.home

import androidx.compose.ui.test.assertContentDescriptionEquals
import androidx.compose.ui.test.assertIsOff
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollToNode
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.blackshield.testing.ui.Screenshots
import com.blackshield.testing.ui.checkAccessibility
import com.blackshield.testing.ui.setThemedContent
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class HomeScreenTest {
    @get:Rule
    val rule = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val calls = mutableListOf<String>()
    private val actions = HomeActions(
        onScanNow = { calls += "scan" },
        onRealTimeChange = { calls += "realTime:$it" },
        onUpdateDefinitions = { calls += "definitions" },
        navigation = HomeNavigation(
            onOpenScan = { calls += "openScan" },
            onOpenThreats = { calls += "openThreats" },
            onOpenWebShield = { calls += "openWebShield" },
            onOpenSchedule = { calls += "openSchedule" },
            onOpenHistory = { calls += "openHistory" }
        )
    )

    @Test
    fun protectedDevice_showsFullScoreAndPassesAccessibilityChecks() {
        rule.setThemedContent { HomeScreen(HomeFixtures.protectedState, actions) }

        rule.onNodeWithTag("protectionLevel").assertTextEquals(context.getString(R.string.home_level_protected))
        rule.onNodeWithTag("securityScore")
            .assertContentDescriptionEquals(context.getString(R.string.home_score_description, 100))
        rule.checkAccessibility()
    }

    @Test
    fun scanNow_startsAScan() {
        rule.setThemedContent { HomeScreen(HomeFixtures.protectedState, actions) }

        rule.onNodeWithTag("homeScanNow").performClick()

        assertEquals(listOf("scan"), calls)
    }

    @Test
    fun atRisk_explainsTheScoreAndLinksEachFixToItsScreen() {
        rule.setThemedContent { HomeScreen(HomeFixtures.atRiskState, actions) }

        rule.onNodeWithTag("protectionLevel").assertTextEquals(context.getString(R.string.home_level_risk))
        rule.onNodeWithTag("homeReviewThreats").performClick()
        rule.onNodeWithTag("home").performScrollToNode(hasTestTag("improve_WEB_SHIELD"))
        rule.onNodeWithTag("improve_WEB_SHIELD").performClick()
        rule.onNodeWithTag("home").performScrollToNode(hasTestTag("moduleRealTime"))
        rule.onNodeWithTag("moduleRealTime").assertIsOff().performClick()

        assertEquals(listOf("openThreats", "openWebShield", "realTime:true"), calls)
        rule.checkAccessibility()
    }

    @Test
    fun screenshot_dark() {
        rule.setThemedContent(darkTheme = true) { HomeScreen(HomeFixtures.attentionState, actions) }
        Screenshots.assertMatchesGolden(rule.onRoot(), "home_dark")
    }

    @Test
    fun screenshot_light() {
        rule.setThemedContent(darkTheme = false) { HomeScreen(HomeFixtures.attentionState, actions) }
        Screenshots.assertMatchesGolden(rule.onRoot(), "home_light")
    }
}
