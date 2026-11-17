import com.blackshield.buildlogic.CopyApkTask
import com.blackshield.buildlogic.NativeFuzzTask
import com.blackshield.buildlogic.NativeGTestTask

plugins {
    alias(libs.plugins.blackshield.android.library)
    alias(libs.plugins.blackshield.hilt)
}

/**
 * Public keys trusted for YARA rule updates (`GET /v1/rules`), as `keyId:base64(SPKI)` entries
 * separated by commas; `blackshield-signatures rules-keygen` prints one. From the Gradle property
 * `blackshield.yaraRulesPublicKeys` or the `BLACKSHIELD_YARA_RULES_PUBLIC_KEYS` environment
 * variable. Empty (the default) means no update is accepted: only the bundled rules are used.
 * Public keys are not secret; the signing key never leaves the publishing machine.
 */
val yaraRulesPublicKeys: String =
    providers
        .gradleProperty("blackshield.yaraRulesPublicKeys")
        .orElse(providers.environmentVariable("BLACKSHIELD_YARA_RULES_PUBLIC_KEYS"))
        .getOrElse("")

android {
    namespace = "com.blackshield.core.scanner"
    ndkVersion = libs.versions.ndk.get()

    buildFeatures {
        buildConfig = true
    }

    defaultConfig {
        buildConfigField("String", "YARA_RULES_PUBLIC_KEYS", "\"" + yaraRulesPublicKeys.replace("\"", "") + "\"")
        consumerProguardFiles("consumer-rules.pro")
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
        externalNativeBuild {
            cmake {
                arguments += listOf("-DANDROID_STL=c++_static")
            }
        }
    }

    testOptions {
        unitTests.all { test ->
            test.useJUnitPlatform()
            // JAZZER_FUZZ=1 turns the @FuzzTest regression runs into real fuzzing (see docs/testing.md).
            System.getenv("JAZZER_FUZZ")?.let { test.environment("JAZZER_FUZZ", it) }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = libs.versions.cmake.get()
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    api(projects.core.data)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.timber)

    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.okhttp.tls)
    // Jazzer fuzz tests for the APK, manifest and certificate parsers (src/test/.../fuzz). They run on the JUnit
    // Platform; the vintage engine keeps the JUnit 4 tests running alongside.
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.jazzer.junit)
    testRuntimeOnly(libs.junit.vintage.engine)
    testRuntimeOnly(libs.junit.platform.launcher)

    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.kotlinx.coroutines.test)
}

// GoogleTest suite for the C++ primitives, built with the NDK and run on a connected device:
//   ./gradlew :core:scanner:connectedNativeTest [-PnativeTestAbi=arm64-v8a] [-PgtestFilter=Sha256*]
val androidComponents = extensions.getByType<com.android.build.api.variant.LibraryAndroidComponentsExtension>()
tasks.register<NativeGTestTask>("connectedNativeTest") {
    group = "verification"
    description = "Builds the native GoogleTest suite and runs it on the connected device."
    sourceDirectory.set(layout.projectDirectory.dir("src/main/cpp"))
    testSourceDirectory.set(layout.projectDirectory.dir("src/nativeTest/cpp"))
    buildDirectory.set(layout.buildDirectory.dir("native-tests"))
    sdkDirectory.set(androidComponents.sdkComponents.sdkDirectory)
    ndkVersion.set(libs.versions.ndk)
    cmakeVersion.set(libs.versions.cmake)
    abi.set(providers.gradleProperty("nativeTestAbi").orElse("x86_64"))
    minSdk.set(libs.versions.minSdk.map(String::toInt))
    gtestFilter.set(providers.gradleProperty("gtestFilter").orElse("*"))
    // -PnativeSanitize=address,undefined runs the suite under AddressSanitizer and UndefinedBehaviorSanitizer.
    sanitize.set(providers.gradleProperty("nativeSanitize").orElse(""))
}

// libFuzzer targets (src/nativeFuzz) with ASan + UBSan on a connected device, seeded from src/nativeFuzz/corpus:
//   ./gradlew :core:scanner:connectedNativeFuzz [-PfuzzSeconds=300]
tasks.register<NativeFuzzTask>("connectedNativeFuzz") {
    group = "verification"
    description = "Builds the native fuzz targets with ASan/UBSan and fuzzes them on the connected device."
    sourceDirectory.set(layout.projectDirectory.dir("src/main/cpp"))
    corpusDirectory.set(layout.projectDirectory.dir("src/nativeFuzz/corpus"))
    buildDirectory.set(layout.buildDirectory.dir("native-fuzz"))
    sdkDirectory.set(androidComponents.sdkComponents.sdkDirectory)
    ndkVersion.set(libs.versions.ndk)
    cmakeVersion.set(libs.versions.cmake)
    abi.set(providers.gradleProperty("nativeTestAbi").orElse("x86_64"))
    minSdk.set(libs.versions.minSdk.map(String::toInt))
    targets.set(listOf("yara_scan_fuzzer"))
    seconds.set(providers.gradleProperty("fuzzSeconds").map(String::toInt).orElse(120))
}

// A real APK with YARA test markers in its DEX code, for the instrumented YARA tests.
val yaraTestApkAsset =
    tasks.register<CopyApkTask>("yaraTestApkAsset") {
        dependsOn(":testing:yara-test-apk:assembleDebug")
        apkDirectory.set(rootProject.layout.projectDirectory.dir("testing/yara-test-apk/build/outputs/apk/debug"))
        fileName.set("yara-test.apk")
        outputDirectory.set(layout.buildDirectory.dir("yara/androidTestAssets"))
    }
androidComponents.onVariants(androidComponents.selector().withBuildType("debug")) { variant ->
    variant.androidTest?.sources?.assets?.addGeneratedSourceDirectory(yaraTestApkAsset, CopyApkTask::outputDirectory)
}
