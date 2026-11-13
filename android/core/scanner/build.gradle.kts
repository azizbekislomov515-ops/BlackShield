import com.blackshield.buildlogic.NativeGTestTask

plugins {
    alias(libs.plugins.blackshield.android.library)
    alias(libs.plugins.blackshield.hilt)
}

android {
    namespace = "com.blackshield.core.scanner"
    ndkVersion = libs.versions.ndk.get()

    defaultConfig {
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
}
