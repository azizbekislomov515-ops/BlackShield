import com.android.build.api.dsl.ApplicationExtension
import com.android.build.api.dsl.LibraryExtension
import com.blackshield.buildlogic.libs
import com.blackshield.buildlogic.library
import com.blackshield.buildlogic.pluginId
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.configure
import org.gradle.kotlin.dsl.dependencies
import org.gradle.kotlin.dsl.project

/** Enables Jetpack Compose (Material 3) on an Android application or library module. */
class AndroidComposeConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        with(target) {
            pluginManager.apply(libs.pluginId("kotlin-compose"))

            pluginManager.withPlugin(libs.pluginId("android-application")) {
                extensions.configure<ApplicationExtension> {
                    buildFeatures { compose = true }
                    defaultConfig { testInstrumentationRunnerArguments += TEST_STORAGE }
                }
            }
            pluginManager.withPlugin(libs.pluginId("android-library")) {
                extensions.configure<LibraryExtension> {
                    buildFeatures { compose = true }
                    defaultConfig { testInstrumentationRunnerArguments += TEST_STORAGE }
                }
            }

            dependencies {
                val bom = platform(libs.library("androidx-compose-bom"))
                add("implementation", bom)
                add("implementation", libs.library("androidx-compose-ui"))
                add("implementation", libs.library("androidx-compose-material3"))
                add("implementation", libs.library("androidx-compose-ui-tooling-preview"))
                add("debugImplementation", libs.library("androidx-compose-ui-tooling"))

                // Compose UI tests with accessibility checks and screenshot goldens (see docs/testing.md).
                add("androidTestImplementation", bom)
                add("androidTestImplementation", libs.library("androidx-compose-ui-test-junit4"))
                add("androidTestImplementation", libs.library("androidx-test-runner"))
                // Compose testing pulls Espresso 3.5, which calls InputManager APIs removed in Android 17.
                add("androidTestImplementation", libs.library("androidx-test-espresso-core"))
                add("debugImplementation", libs.library("androidx-compose-ui-test-manifest"))
                add("androidTestUtil", libs.library("androidx-test-services"))
                if (path != UI_TESTING) add("androidTestImplementation", project(UI_TESTING))
            }
        }
    }
}

private const val UI_TESTING = ":testing:ui"

/** Screenshots are written through the test storage service, which pulls them into build/outputs. */
private val TEST_STORAGE = mapOf("useTestStorageService" to "true")
