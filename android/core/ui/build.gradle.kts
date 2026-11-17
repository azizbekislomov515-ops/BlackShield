plugins {
    alias(libs.plugins.blackshield.android.library)
    alias(libs.plugins.blackshield.android.compose)
}

android {
    namespace = "com.blackshield.core.ui"
}

dependencies {
    api(projects.core.designsystem)
    implementation(projects.core.data)
}
