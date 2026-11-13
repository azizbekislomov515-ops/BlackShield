plugins {
    alias(libs.plugins.blackshield.android.feature)
}

android {
    namespace = "com.blackshield.feature.settings"
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(projects.core.data)
    implementation(projects.core.sync)
    implementation(libs.androidx.activity.compose)
}
