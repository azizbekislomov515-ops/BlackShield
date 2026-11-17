plugins {
    alias(libs.plugins.blackshield.android.feature)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "com.blackshield.feature.threats"
}

dependencies {
    implementation(projects.core.data)
    implementation(projects.core.scanner)
    implementation(projects.core.ui)
    implementation(projects.feature.scan)

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.android)

    testImplementation(libs.junit)
}
