plugins {
    alias(libs.plugins.blackshield.android.feature)
}

android {
    namespace = "com.blackshield.feature.home"
}

dependencies {
    implementation(projects.core.data)
    implementation(projects.core.sync)
    implementation(projects.core.ui)
    implementation(projects.feature.scan)
    implementation(projects.feature.protection)
    implementation(projects.feature.webshield)
    implementation(libs.androidx.activity.compose)

    testImplementation(libs.junit)
}
