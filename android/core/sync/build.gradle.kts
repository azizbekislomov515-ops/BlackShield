plugins {
    alias(libs.plugins.blackshield.android.library)
    alias(libs.plugins.blackshield.hilt)
}

android {
    namespace = "com.blackshield.core.sync"
}

dependencies {
    implementation(projects.core.data)
    implementation(projects.core.network)
    implementation(projects.core.scanner)

    implementation(libs.androidx.work.runtime.ktx)
    implementation(libs.androidx.hilt.work)
    ksp(libs.androidx.hilt.compiler)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.timber)

    testImplementation(libs.okhttp.mockwebserver)
    testImplementation(libs.kotlinx.coroutines.test)

    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.kotlinx.coroutines.test)
}
