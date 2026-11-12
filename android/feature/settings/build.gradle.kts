plugins {
    alias(libs.plugins.blackshield.android.feature)
}

android {
    namespace = "com.blackshield.feature.settings"
}

dependencies {
    implementation(projects.core.data)
}
