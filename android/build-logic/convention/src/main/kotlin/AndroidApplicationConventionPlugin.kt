import com.android.build.api.dsl.ApplicationExtension
import com.blackshield.buildlogic.configureJava
import com.blackshield.buildlogic.configureStrict
import com.blackshield.buildlogic.intVersion
import com.blackshield.buildlogic.libs
import com.blackshield.buildlogic.pluginId
import com.blackshield.buildlogic.versionOf
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.configure

class AndroidApplicationConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        with(target) {
            pluginManager.apply(libs.pluginId("android-application"))

            extensions.configure<ApplicationExtension> {
                compileSdk = libs.intVersion("compileSdk")
                // Used to strip debug symbols from packaged native libraries.
                ndkVersion = libs.versionOf("ndk")
                defaultConfig {
                    minSdk = libs.intVersion("minSdk")
                    targetSdk = libs.intVersion("targetSdk")
                    testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
                }
                compileOptions { configureJava() }
                lint { configureStrict() }
            }
        }
    }
}
