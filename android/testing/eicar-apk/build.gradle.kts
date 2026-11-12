// A harmless app with no code, no permissions and no activities. Its role mirrors the EICAR test
// file: debug builds of BlackShield seed this APK's SHA-256 as a "malware" signature, so detection
// can be verified end to end without real malware:
//   ./gradlew :testing:eicar-apk:installDebug :app:installDebug   (then "Scan now")
plugins {
    alias(libs.plugins.blackshield.android.application)
}

android {
    namespace = "com.blackshield.testing.eicar"

    defaultConfig {
        applicationId = "com.blackshield.testing.eicar"
        versionCode = 1
        versionName = "1.0"
    }
}
