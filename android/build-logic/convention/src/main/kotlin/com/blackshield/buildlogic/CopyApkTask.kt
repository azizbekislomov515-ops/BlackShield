package com.blackshield.buildlogic

import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction

/** Copies the single APK in [apkDirectory] to [outputDirectory]/[fileName], e.g. as a test asset. */
@CacheableTask
abstract class CopyApkTask : DefaultTask() {
    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val apkDirectory: DirectoryProperty

    @get:Input
    abstract val fileName: Property<String>

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    @TaskAction
    fun run() {
        val apks = apkDirectory.get().asFile.listFiles { file -> file.extension == "apk" }.orEmpty()
        val apk = apks.singleOrNull() ?: error("Expected one APK in ${apkDirectory.get()}, found ${apks.size}")
        val out = outputDirectory.get().asFile
        out.deleteRecursively()
        out.mkdirs()
        apk.copyTo(out.resolve(fileName.get()))
    }
}
