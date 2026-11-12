plugins {
    alias(libs.plugins.blackshield.android.application)
    alias(libs.plugins.blackshield.android.compose)
    alias(libs.plugins.blackshield.hilt)
}

android {
    namespace = "com.blackshield.app"

    defaultConfig {
        applicationId = "com.blackshield.app"
        versionCode = 1
        versionName = "0.1.0"
        ndk {
            // Must match the ABIs built by :core:scanner.
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    buildFeatures {
        buildConfig = true
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
}

dependencies {
    implementation(projects.core.scanner)
    implementation(projects.core.data)
    implementation(projects.core.network)
    implementation(projects.feature.scan)
    implementation(projects.feature.protection)
    implementation(projects.feature.webshield)
    implementation(projects.feature.settings)

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.work.runtime.ktx)
    implementation(libs.androidx.hilt.work)
    implementation(libs.timber)

    testImplementation(libs.junit)
}
