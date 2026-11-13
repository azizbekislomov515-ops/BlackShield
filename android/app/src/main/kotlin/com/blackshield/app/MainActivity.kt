package com.blackshield.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import com.blackshield.app.ui.theme.BlackShieldTheme
import com.blackshield.feature.scan.ScanRoute
import com.blackshield.feature.settings.SettingsRoute
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent {
            BlackShieldTheme {
                BlackShieldApp()
            }
        }
    }
}

private enum class Destination(@StringRes val label: Int, @DrawableRes val icon: Int) {
    SCAN(R.string.nav_scan, R.drawable.ic_nav_scan),
    SETTINGS(R.string.nav_settings, R.drawable.ic_nav_settings)
}

@Composable
private fun BlackShieldApp() {
    var destination by rememberSaveable { mutableStateOf(Destination.SCAN) }
    Scaffold(
        bottomBar = {
            NavigationBar {
                Destination.entries.forEach { item ->
                    NavigationBarItem(
                        selected = item == destination,
                        onClick = { destination = item },
                        icon = { Icon(painterResource(item.icon), contentDescription = null) },
                        label = { Text(stringResource(item.label)) }
                    )
                }
            }
        }
    ) { innerPadding ->
        // Each screen has its own Scaffold; consuming the insets here stops it adding them twice.
        val content = Modifier.fillMaxSize().padding(innerPadding).consumeWindowInsets(innerPadding)
        when (destination) {
            Destination.SCAN -> ScanRoute(modifier = content)
            Destination.SETTINGS -> SettingsRoute(modifier = content)
        }
    }
}
