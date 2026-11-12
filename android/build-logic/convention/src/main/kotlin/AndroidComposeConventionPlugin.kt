import com.android.build.api.dsl.ApplicationExtension
import com.android.build.api.dsl.LibraryExtension
import com.blackshield.buildlogic.libs
import com.blackshield.buildlogic.library
import com.blackshield.buildlogic.pluginId
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.configure
import org.gradle.kotlin.dsl.dependencies

/** Enables Jetpack Compose (Material 3) on an Android application or library module. */
class AndroidComposeConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        with(target) {
            pluginManager.apply(libs.pluginId("kotlin-compose"))

            pluginManager.withPlugin(libs.pluginId("android-application")) {
                extensions.configure<ApplicationExtension> { buildFeatures { compose = true } }
            }
            pluginManager.withPlugin(libs.pluginId("android-library")) {
                extensions.configure<LibraryExtension> { buildFeatures { compose = true } }
            }

            dependencies {
                val bom = platform(libs.library("androidx-compose-bom"))
                add("implementation", bom)
                add("implementation", libs.library("androidx-compose-ui"))
                add("implementation", libs.library("androidx-compose-material3"))
                add("implementation", libs.library("androidx-compose-ui-tooling-preview"))
                add("debugImplementation", libs.library("androidx-compose-ui-tooling"))
            }
        }
    }
}
