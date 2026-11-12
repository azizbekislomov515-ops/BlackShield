plugins {
    alias(libs.plugins.blackshield.android.library)
    alias(libs.plugins.blackshield.hilt)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "com.blackshield.core.network"

    buildFeatures {
        buildConfig = true
    }

    buildTypes {
        debug {
            // 10.0.2.2 is the host machine as seen from the Android emulator (docker compose API).
            buildConfigField("String", "API_BASE_URL", "\"http://10.0.2.2:8000/\"")
        }
        release {
            buildConfigField("String", "API_BASE_URL", "\"https://api.blackshield.invalid/\"")
        }
    }
}

dependencies {
    api(libs.retrofit)
    implementation(libs.retrofit.kotlinx.serialization)
    implementation(libs.okhttp)
    implementation(libs.okhttp.logging)
    api(libs.kotlinx.serialization.json)
}
