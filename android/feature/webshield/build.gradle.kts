plugins {
    alias(libs.plugins.blackshield.android.feature)
}

android {
    namespace = "com.blackshield.feature.webshield"
}

dependencies {
    implementation(projects.core.data)
    implementation(projects.core.network)
    implementation(projects.core.sync)

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.kotlinx.coroutines.android)

    testImplementation(libs.kotlinx.coroutines.test)

    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.kotlinx.coroutines.test)
}
