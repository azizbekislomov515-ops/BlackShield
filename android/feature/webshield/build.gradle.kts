plugins {
    alias(libs.plugins.blackshield.android.feature)
}

android {
    namespace = "com.blackshield.feature.webshield"
}

dependencies {
    implementation(projects.core.network)
}
