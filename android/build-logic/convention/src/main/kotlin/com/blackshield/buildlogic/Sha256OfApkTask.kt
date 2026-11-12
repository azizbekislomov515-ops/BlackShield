package com.blackshield.buildlogic

import java.security.MessageDigest
import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction

/** Writes the lower-case hex SHA-256 of the single APK in [apkDirectory] to [outputFile]. */
@CacheableTask
abstract class Sha256OfApkTask : DefaultTask() {
    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val apkDirectory: DirectoryProperty

    @get:OutputFile
    abstract val outputFile: RegularFileProperty

    @TaskAction
    fun run() {
        val apks = apkDirectory.get().asFile.listFiles { file -> file.extension == "apk" }.orEmpty()
        val apk = apks.singleOrNull() ?: error("Expected one APK in ${apkDirectory.get()}, found ${apks.size}")
        val digest = MessageDigest.getInstance("SHA-256")
        apk.inputStream().use { input ->
            val buffer = ByteArray(BUFFER_SIZE)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        outputFile.get().asFile.writeText(digest.digest().joinToString("") { "%02x".format(it) })
    }

    private companion object {
        const val BUFFER_SIZE = 64 * 1024
    }
}
