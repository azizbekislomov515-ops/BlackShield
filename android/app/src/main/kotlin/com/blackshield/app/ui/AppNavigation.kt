package com.blackshield.app.ui

import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import com.blackshield.app.R
import com.blackshield.core.designsystem.R as DsR
import com.blackshield.core.designsystem.component.BsTopBar
import com.blackshield.feature.protection.troubleshooting.TroubleshootingRoute
import com.blackshield.feature.threats.history.HistoryRoute
import com.blackshield.feature.webshield.WebShieldRoute

/** The four main destinations, always in the bottom bar. */
enum class Tab(@StringRes val label: Int, @DrawableRes val icon: Int) {
    HOME(R.string.nav_home, DsR.drawable.bs_ic_home),
    SCAN(R.string.nav_scan, DsR.drawable.bs_ic_radar),
    THREATS(R.string.nav_threats, DsR.drawable.bs_ic_report),
    SETTINGS(R.string.nav_settings, DsR.drawable.bs_ic_tune)
}

/** Screens opened on top of a tab, with a back button. */
enum class Overlay { WEB_SHIELD, HISTORY, TROUBLESHOOTING }

@Composable
fun AppNavigationBar(selected: Tab, onSelect: (Tab) -> Unit) {
    NavigationBar(containerColor = MaterialTheme.colorScheme.surfaceContainerLow) {
        Tab.entries.forEach { tab ->
            NavigationBarItem(
                selected = tab == selected,
                onClick = { onSelect(tab) },
                // The label already names the destination; the icon is decorative.
                icon = { Icon(painterResource(tab.icon), contentDescription = null) },
                label = { Text(stringResource(tab.label)) },
                colors =
                    NavigationBarItemDefaults.colors(
                        selectedIconColor = MaterialTheme.colorScheme.primary,
                        selectedTextColor = MaterialTheme.colorScheme.primary,
                        indicatorColor = MaterialTheme.colorScheme.primary.copy(alpha = INDICATOR_ALPHA)
                    ),
                modifier = Modifier.testTag("tab_${tab.name}")
            )
        }
    }
}

@Composable
fun OverlayHost(overlay: Overlay, onBack: () -> Unit) {
    when (overlay) {
        Overlay.HISTORY -> HistoryRoute(onBack = onBack)

        Overlay.TROUBLESHOOTING -> TroubleshootingRoute(onBack = onBack)

        Overlay.WEB_SHIELD ->
            Scaffold(
                topBar = {
                    BsTopBar(
                        stringResource(R.string.nav_web_shield),
                        onBack = onBack,
                        backDescription = stringResource(R.string.nav_back)
                    )
                }
            ) { padding -> WebShieldRoute(modifier = Modifier.fillMaxSize().padding(padding)) }
    }
}

private const val INDICATOR_ALPHA = 0.16f
