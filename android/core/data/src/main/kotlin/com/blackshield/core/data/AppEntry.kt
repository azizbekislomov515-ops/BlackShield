package com.blackshield.core.data

import android.content.Context
import android.content.Intent

/**
 * How the app's own notifications, tile and services open its UI.
 *
 * The launcher activity is exported, so any app can start it with any extras. Deep-link extras (a scan result to
 * show, a screen to open) are therefore honoured only when the activity is started through [INTERNAL_ENTRY], a
 * non-exported alias that only this app's PendingIntents can target. Otherwise another app could make BlackShield
 * display a forged verdict.
 */
object AppEntry {
    /** Component class of the non-exported alias of the main activity (see the app manifest). */
    const val INTERNAL_ENTRY = "com.blackshield.app.InternalEntry"

    fun intent(context: Context): Intent = Intent(Intent.ACTION_MAIN).setClassName(context, INTERNAL_ENTRY)
}
