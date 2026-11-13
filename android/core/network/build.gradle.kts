plugins {
    alias(libs.plugins.blackshield.android.library)
    alias(libs.plugins.blackshield.hilt)
    alias(libs.plugins.kotlin.serialization)
}

/**
 * Backend connection settings, from Gradle properties (`-P...`, ~/.gradle/gradle.properties) or
 * environment variables. Nothing secret is committed:
 *
 * - `blackshield.apiBaseUrl` / `BLACKSHIELD_API_BASE_URL`: overrides the per-build-type default.
 * - `blackshield.apiKey` / `BLACKSHIELD_API_KEY`: the app build's API key (see docs/sync-protocol.md).
 * - `blackshield.certificatePins` / `BLACKSHIELD_CERTIFICATE_PINS`: comma-separated
 *   `host=sha256/<base64>` entries; empty disables pinning. Always include a backup pin.
 */
fun backendSetting(property: String, env: String): Provider<String> =
    providers.gradleProperty(property).orElse(providers.environmentVariable(env))

val apiBaseUrlOverride = backendSetting("blackshield.apiBaseUrl", "BLACKSHIELD_API_BASE_URL")
val apiKey = backendSetting("blackshield.apiKey", "BLACKSHIELD_API_KEY").orElse("")
val certificatePins = backendSetting("blackshield.certificatePins", "BLACKSHIELD_CERTIFICATE_PINS").orElse("")

fun quoted(value: String): String = "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

android {
    namespace = "com.blackshield.core.network"

    buildFeatures {
        buildConfig = true
    }

    defaultConfig {
        buildConfigField("String", "API_KEY", quoted(apiKey.get()))
        buildConfigField("String", "CERTIFICATE_PINS", quoted(certificatePins.get()))
    }

    buildTypes {
        debug {
            // 10.0.2.2 is the host machine as seen from the Android emulator (docker compose API).
            buildConfigField("String", "API_BASE_URL", quoted(apiBaseUrlOverride.getOrElse("http://10.0.2.2:8000/")))
        }
        release {
            buildConfigField(
                "String",
                "API_BASE_URL",
                quoted(apiBaseUrlOverride.getOrElse("https://api.blackshield.invalid/"))
            )
        }
    }
}

dependencies {
    api(libs.retrofit)
    implementation(libs.retrofit.kotlinx.serialization)
    api(libs.okhttp)
    implementation(libs.okhttp.logging)
    api(libs.kotlinx.serialization.json)

    testImplementation(libs.okhttp.mockwebserver)
    testImplementation(libs.okhttp.tls)
    testImplementation(libs.kotlinx.coroutines.test)
}
