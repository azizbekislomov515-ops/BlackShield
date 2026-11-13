package com.blackshield.core.scanner.analysis

import com.blackshield.core.scanner.apps.InstalledApp

/**
 * Builds an [AppProfile] for an installed app (static analysis: nothing is executed).
 *
 * A scan opens one [Session]: device-wide facts (launcher activities, enabled accessibility
 * services, active device admins, permission protection levels) are read once per session
 * instead of once per app.
 */
interface ApkAnalyzer {
    fun startSession(): Session

    /**
     * Profiles an APK file that is not installed (a download about to be installed). Null if the
     * file is not a parseable APK. The profile has [AppProfile.isArchive] set.
     */
    fun analyzeArchive(path: String): AppProfile?

    fun interface Session {
        /** Never throws for a single app's bad data: what could not be read goes into [AppProfile.analysisGaps]. */
        suspend fun analyze(app: InstalledApp): AppProfile
    }
}
