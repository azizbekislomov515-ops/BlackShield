// Shared helpers for Compose UI tests: themed content, accessibility checks and screenshot goldens.
plugins {
    alias(libs.plugins.blackshield.android.library)
    alias(libs.plugins.blackshield.android.compose)
}

android {
    namespace = "com.blackshield.testing.ui"
}

dependencies {
    api(platform(libs.androidx.compose.bom))
    api(libs.androidx.compose.ui.test.junit4)
    api(libs.androidx.compose.ui.test.junit4.accessibility)
    api(libs.androidx.test.ext.junit)
    api(libs.junit)
    implementation(libs.androidx.test.runner)
    implementation(libs.androidx.test.core.ktx)
    implementation(projects.core.designsystem)
}
