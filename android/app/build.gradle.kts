import com.android.build.api.variant.BuildConfigField
import com.blackshield.buildlogic.CopyApkTask
import com.blackshield.buildlogic.Sha256OfApkTask

plugins {
    alias(libs.plugins.blackshield.android.application)
    alias(libs.plugins.blackshield.android.compose)
    alias(libs.plugins.blackshield.hilt)
}

// Debug builds seed the SHA-256 of the harmless :testing:eicar-apk as a malware signature so the
// detection flow can be verified end to end (see testing/eicar-apk/build.gradle.kts).
val eicarTestApkSha256 =
    tasks.register<Sha256OfApkTask>("eicarTestApkSha256") {
        dependsOn(":testing:eicar-apk:assembleDebug")
        apkDirectory.set(rootProject.layout.projectDirectory.dir("testing/eicar-apk/build/outputs/apk/debug"))
        outputFile.set(layout.buildDirectory.file("eicar/eicar-test-apk.sha256"))
    }

// The instrumented real-time protection test installs the same APK, so it ships as a test asset.
val eicarTestApkAsset =
    tasks.register<CopyApkTask>("eicarTestApkAsset") {
        dependsOn(":testing:eicar-apk:assembleDebug")
        apkDirectory.set(rootProject.layout.projectDirectory.dir("testing/eicar-apk/build/outputs/apk/debug"))
        fileName.set("eicar-test.apk")
        outputDirectory.set(layout.buildDirectory.dir("eicar/androidTestAssets"))
    }

androidComponents {
    onVariants(selector().withBuildType("debug")) { variant ->
        variant.androidTest?.sources?.assets?.addGeneratedSourceDirectory(
            eicarTestApkAsset,
            CopyApkTask::outputDirectory
        )
        variant.buildConfigFields?.put(
            "EICAR_TEST_APK_SHA256",
            eicarTestApkSha256.flatMap { it.outputFile }.map { file ->
                BuildConfigField("String", "\"${file.asFile.readText().trim()}\"", "SHA-256 of :testing:eicar-apk")
            }
        )
    }
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
        // Release configuration (R8, not debuggable) signed with the debug key, for performance
        // measurements on devices: debuggable builds are several times slower at rendering.
        create("benchmark") {
            initWith(getByName("release"))
            signingConfig = signingConfigs.getByName("debug")
            matchingFallbacks += listOf("release")
            applicationIdSuffix = ".benchmark"
        }
    }
}

dependencies {
    implementation(projects.core.scanner)
    implementation(projects.core.data)
    implementation(projects.core.network)
    implementation(projects.core.sync)
    implementation(projects.feature.scan)
    implementation(projects.feature.protection)
    implementation(projects.feature.webshield)
    implementation(projects.feature.settings)

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.work.runtime.ktx)
    implementation(libs.androidx.hilt.work)
    implementation(libs.androidx.hilt.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.timber)

    testImplementation(libs.junit)

    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.kotlinx.coroutines.test)
}
