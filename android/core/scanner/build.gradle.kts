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
