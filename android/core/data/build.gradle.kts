plugins {
    alias(libs.plugins.blackshield.android.library)
    alias(libs.plugins.blackshield.hilt)
    alias(libs.plugins.room)
}

android {
    namespace = "com.blackshield.core.data"
}

room {
    schemaDirectory("$projectDir/schemas")
}

dependencies {
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)

    api(libs.androidx.datastore.preferences)
    implementation(libs.kotlinx.coroutines.android)
}
