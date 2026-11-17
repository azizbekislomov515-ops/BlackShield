plugins {
    alias(libs.plugins.blackshield.android.library)
    alias(libs.plugins.blackshield.android.compose)
}

android {
    namespace = "com.blackshield.core.designsystem"
}

dependencies {
    // Aligns lifecycle-runtime with the rest of the app; Compose alone pulls an older one whose lint checks are obsolete.
    implementation(libs.androidx.lifecycle.runtime.ktx)
}
