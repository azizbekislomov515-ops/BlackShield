package com.blackshield.testing.yara

/**
 * Harmless strings that end up in this APK's `classes.dex` string table. Nothing reads them: they
 * exist only so YARA rules have something to find, like the EICAR test file for antivirus engines.
 */
object YaraTestMarkers {
    /** Matched by the bundled rule `BlackShield_Test_File` (severity critical). */
    const val BUNDLED_RULE_MARKER = "X5O-BLACKSHIELD-YARA-TEST-FILE-1d8e"

    /** Matched by no bundled rule: tests publish a rule for it to check that rule updates take effect. */
    const val UPDATE_PROBE_MARKER = "BLACKSHIELD-YARA-UPDATE-PROBE-5c21"
}
