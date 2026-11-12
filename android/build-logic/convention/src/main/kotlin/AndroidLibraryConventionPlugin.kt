import com.android.build.api.dsl.LibraryExtension
import com.blackshield.buildlogic.configureJava
import com.blackshield.buildlogic.configureStrict
import com.blackshield.buildlogic.intVersion
import com.blackshield.buildlogic.libs
import com.blackshield.buildlogic.library
import com.blackshield.buildlogic.pluginId
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.configure
import org.gradle.kotlin.dsl.dependencies

class AndroidLibraryConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        with(target) {
            pluginManager.apply(libs.pluginId("android-library"))

            extensions.configure<LibraryExtension> {
                compileSdk = libs.intVersion("compileSdk")
                defaultConfig {
                    minSdk = libs.intVersion("minSdk")
                    testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
                }
                testOptions.targetSdk = libs.intVersion("targetSdk")
                compileOptions { configureJava() }
                lint {
                    targetSdk = libs.intVersion("targetSdk")
                    configureStrict()
                }
            }

            dependencies {
                add("testImplementation", libs.library("junit"))
            }
        }
    }
}
