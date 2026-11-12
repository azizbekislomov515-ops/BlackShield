package com.blackshield.buildlogic

import com.android.build.api.dsl.CompileOptions
import com.android.build.api.dsl.Lint
import org.gradle.api.JavaVersion
import org.gradle.api.Project
import org.gradle.api.artifacts.MinimalExternalModuleDependency
import org.gradle.api.artifacts.VersionCatalog
import org.gradle.api.artifacts.VersionCatalogsExtension
import org.gradle.api.provider.Provider
import org.gradle.kotlin.dsl.getByType

internal val Project.libs: VersionCatalog
    get() = extensions.getByType<VersionCatalogsExtension>().named("libs")

internal fun VersionCatalog.versionOf(alias: String): String = findVersion(alias).get().requiredVersion

internal fun VersionCatalog.intVersion(alias: String): Int = versionOf(alias).toInt()

internal fun VersionCatalog.library(alias: String): Provider<MinimalExternalModuleDependency> = findLibrary(alias).get()

internal fun VersionCatalog.pluginId(alias: String): String = findPlugin(alias).get().get().pluginId

internal fun CompileOptions.configureJava() {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

/**
 * Strict lint: every warning fails the build. Checks whose result depends only on the
 * calendar (newer library/AGP/SDK releases) are disabled so CI does not break on its own;
 * keep dependencies current through the version catalog instead.
 */
internal fun Lint.configureStrict() {
    abortOnError = true
    warningsAsErrors = true
    checkReleaseBuilds = true
    checkDependencies = false
    disable +=
        setOf(
            "GradleDependency",
            "NewerVersionAvailable",
            "AndroidGradlePluginVersion",
            "OldTargetApi",
        )
}
