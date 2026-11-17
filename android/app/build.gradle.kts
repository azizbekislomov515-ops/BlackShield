import com.android.build.api.variant.BuildConfigField
import com.blackshield.buildlogic.CopyApkTask
import com.blackshield.buildlogic.Sha256OfApkTask
import org.gradle.api.provider.Provider

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

/** A Gradle property, or else an environment variable (CI passes secrets as environment variables). */
fun setting(property: String, environment: String): Provider<String> =
    providers.gradleProperty(property).orElse(providers.environmentVariable(environment))

// Versioning: one semantic version in gradle.properties; the version code is derived from it, so every release
// bumps both. MAJOR.MINOR.PATCH -> MAJOR * 10000 + MINOR * 100 + PATCH (MINOR and PATCH stay below 100).
val appVersionName: String = setting("blackshield.versionName", "BLACKSHIELD_VERSION_NAME").get()
val appVersionCode: Int =
    appVersionName.split('.').map(String::toInt).let { (major, minor, patch) ->
        require(minor < 100 && patch < 100) { "Version $appVersionName: minor and patch must be below 100" }
        major * 10_000 + minor * 100 + patch
    }

// Release signing from the environment (CI secrets) or ~/.gradle/gradle.properties. Never in the repository.
val releaseKeystore = setting("blackshield.keystoreFile", "BLACKSHIELD_KEYSTORE_FILE")
val requireReleaseSigning = setting("blackshield.requireReleaseSigning", "BLACKSHIELD_REQUIRE_RELEASE_SIGNING")
    .map(String::toBoolean).getOrElse(false)

// SHA-256 of the certificates allowed to sign release builds (Play app signing key, upload key), comma-separated.
// A release signed by anything else shows a "modified copy" warning (AppIntegrity). Empty disables the check.
val releaseCertSha256: String = setting(
    "blackshield.releaseCertSha256",
    "BLACKSHIELD_RELEASE_CERT_SHA256"
).getOrElse("")

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

    // English, Uzbek and Russian; library translations for other languages are left out of the APK.
    androidResources {
        localeFilters += listOf("en", "uz", "ru")
    }

    defaultConfig {
        applicationId = "com.blackshield.app"
        versionCode = appVersionCode
        versionName = appVersionName
        buildConfigField("String", "RELEASE_CERT_SHA256", "\"${releaseCertSha256.replace("\"", "")}\"")
        ndk {
            // Must match the ABIs built by :core:scanner.
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    buildFeatures {
        buildConfig = true
    }

    signingConfigs {
        if (releaseKeystore.isPresent) {
            create("release") {
                storeFile = file(releaseKeystore.get())
                storePassword = setting("blackshield.keystorePassword", "BLACKSHIELD_KEYSTORE_PASSWORD").get()
                keyAlias = setting("blackshield.keyAlias", "BLACKSHIELD_KEY_ALIAS").get()
                keyPassword = setting("blackshield.keyPassword", "BLACKSHIELD_KEY_PASSWORD").get()
            }
        }
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
        }
        release {
            signingConfig = signingConfigs.findByName("release")
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
    implementation(projects.core.designsystem)
    implementation(projects.core.ui)
    implementation(projects.feature.home)
    implementation(projects.feature.scan)
    implementation(projects.feature.threats)
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

// CI sets blackshield.requireReleaseSigning so a missing secret fails the build instead of producing an unsigned APK.
if (requireReleaseSigning) {
    check(releaseKeystore.isPresent) { "Release signing is required but BLACKSHIELD_KEYSTORE_FILE is not set" }
}
