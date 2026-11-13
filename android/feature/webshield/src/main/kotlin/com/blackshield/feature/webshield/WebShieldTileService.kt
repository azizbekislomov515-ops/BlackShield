package com.blackshield.feature.webshield

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.blackshield.core.data.prefs.UserPreferencesRepository
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/** Quick settings tile: shows Web Shield's state and toggles it. */
@AndroidEntryPoint
class WebShieldTileService : TileService() {
    @Inject lateinit var runtime: WebShieldRuntime

    @Inject lateinit var controller: WebShieldController

    @Inject lateinit var preferences: UserPreferencesRepository

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var listening: Job? = null

    override fun onStartListening() {
        listening = scope.launch { runtime.status.collect(::render) }
    }

    override fun onStopListening() {
        listening?.cancel()
    }

    override fun onClick() {
        val on = runtime.status.value is WebShieldStatus.On || runtime.status.value == WebShieldStatus.Starting
        when {
            on -> scope.launch { controller.disable() }

            // The VPN permission dialog needs an activity: open the app, which explains it first.
            controller.consentIntent() != null -> openApp()

            else -> scope.launch { controller.enable() }
        }
    }

    @SuppressLint("StartActivityAndCollapseDeprecated")
    private fun openApp() {
        val launch =
            packageManager.getLaunchIntentForPackage(
                packageName
            )?.putExtra(WebShieldNotifications.EXTRA_SHOW_WEB_SHIELD, true)
                ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 0, launch, PendingIntent.FLAG_IMMUTABLE))
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(launch)
        }
    }

    private fun render(status: WebShieldStatus) {
        val tile = qsTile ?: return
        tile.state =
            when (status) {
                is WebShieldStatus.On -> Tile.STATE_ACTIVE
                WebShieldStatus.Starting -> Tile.STATE_ACTIVE
                else -> Tile.STATE_INACTIVE
            }
        tile.label = getString(R.string.webshield_tile_label)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle =
                when (status) {
                    is WebShieldStatus.On -> getString(R.string.webshield_tile_on)
                    WebShieldStatus.Starting -> getString(R.string.webshield_tile_starting)
                    else -> getString(R.string.webshield_tile_off)
                }
        }
        tile.updateTile()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}
