import com.blackshield.buildlogic.libs
import com.blackshield.buildlogic.library
import com.blackshield.buildlogic.pluginId
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.dependencies
import org.gradle.kotlin.dsl.project

/** A feature module: Android library + Compose + Hilt with ViewModel support. */
class AndroidFeatureConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        with(target) {
            pluginManager.apply(libs.pluginId("blackshield-android-library"))
            pluginManager.apply(libs.pluginId("blackshield-android-compose"))
            pluginManager.apply(libs.pluginId("blackshield-hilt"))

            dependencies {
                add("implementation", project(":core:designsystem"))
                add("implementation", libs.library("androidx-lifecycle-runtime-compose"))
                add("implementation", libs.library("androidx-lifecycle-viewmodel-compose"))
                add("implementation", libs.library("androidx-hilt-lifecycle-viewmodel-compose"))
                add("implementation", libs.library("timber"))
            }
        }
    }
}
