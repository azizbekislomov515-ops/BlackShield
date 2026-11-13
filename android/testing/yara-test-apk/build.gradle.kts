// A harmless app whose DEX code contains YARA test markers (see YaraTestMarkers.kt), the YARA
// counterpart of :testing:eicar-apk. Used by the instrumented tests of :core:scanner (copied in
// as an androidTest asset) and for manual end-to-end checks:
//   ./gradlew :testing:yara-test-apk:assembleDebug   (then copy the APK to Download/)
plugins {
    alias(libs.plugins.blackshield.android.application)
}

android {
    namespace = "com.blackshield.testing.yara"

    defaultConfig {
        applicationId = "com.blackshield.testing.yara"
        versionCode = 1
        versionName = "1.0"
    }
}
