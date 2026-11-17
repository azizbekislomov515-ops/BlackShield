package com.blackshield.buildlogic

import java.io.File
import org.gradle.api.logging.Logger
import org.gradle.process.ExecOperations

/**
 * Builds NDK executables with the module's CMake project and runs them on the connected device (honours
 * ANDROID_SERIAL). Shared by the GoogleTest and libFuzzer tasks.
 */
internal class NativeDeviceRunner(
    private val exec: ExecOperations,
    private val logger: Logger,
    sdk: File,
    ndkVersion: String,
    cmakeVersion: String
) {
    private val exe = if (System.getProperty("os.name").startsWith("Windows")) ".exe" else ""
    private val cmake = sdk.resolve("cmake/$cmakeVersion/bin/cmake$exe")
    private val ninja = sdk.resolve("cmake/$cmakeVersion/bin/ninja$exe")
    private val ndk = sdk.resolve("ndk/$ndkVersion")
    val adb: File = sdk.resolve("platform-tools/adb$exe")

    init {
        listOf(cmake, ninja, ndk, adb).forEach {
            require(it.exists()) { "Missing $it (install it with the SDK manager)" }
        }
    }

    /** What to build: the CMake project in [source] for [abi], with extra CMake [options]. */
    data class Build(
        val source: File,
        val buildDir: File,
        val abi: String,
        val minSdk: Int,
        val options: List<String>,
        val targets: List<String>
    )

    /** Configures and builds [build]; returns the binaries of its targets. */
    fun build(build: Build): List<File> {
        run(
            listOf(
                cmake.path, "-S", build.source.path, "-B", build.buildDir.path, "-G", "Ninja",
                "-DCMAKE_MAKE_PROGRAM=${ninja.path}",
                "-DCMAKE_TOOLCHAIN_FILE=${ndk.resolve("build/cmake/android.toolchain.cmake").path}",
                "-DANDROID_ABI=${build.abi}",
                "-DANDROID_PLATFORM=android-${build.minSdk}",
                "-DANDROID_STL=c++_static",
                "-DCMAKE_BUILD_TYPE=Release",
            ) + build.options
        )
        run(listOf(cmake.path, "--build", build.buildDir.path, "--target") + build.targets)
        return build.targets.map { target -> build.buildDir.walkTopDown().first { it.isFile && it.name == target } }
    }

    /**
     * The sanitizer runtime the binaries were linked against, if any: Android only has shared sanitizer
     * runtimes, so it is pushed next to them and found through LD_LIBRARY_PATH.
     */
    fun sanitizerRuntime(sanitize: String, abi: String): File? {
        val library = when {
            "address" in sanitize -> "asan"
            "undefined" in sanitize -> "ubsan_standalone"
            else -> return null
        }
        val arch = CLANG_ARCH.getValue(abi)
        val prebuilt = ndk.resolve("toolchains/llvm/prebuilt").listFiles().orEmpty().single { it.isDirectory }
        return prebuilt.resolve("lib/clang").listFiles().orEmpty()
            .map { it.resolve("lib/linux/libclang_rt.$library-$arch-android.so") }
            .first { it.exists() }
    }

    fun push(local: File, remote: String) = run(listOf(adb.path, "push", local.path, remote))

    fun pull(remote: String, local: File) = run(listOf(adb.path, "pull", remote, local.path))

    fun shell(command: String) = run(listOf(adb.path, "shell", command))

    /** Runs [command] on the device; returns its exit status instead of failing. */
    fun shellStatus(command: String): Int = exec.exec {
        commandLine(adb.path, "shell", command) // adb passes the device-side exit status through
        isIgnoreExitValue = true
    }.exitValue

    fun shellQuietly(command: String) {
        exec.exec {
            commandLine(adb.path, "shell", command)
            isIgnoreExitValue = true
        }
    }

    fun lifecycle(message: String) = logger.lifecycle(message)

    private fun run(command: List<String>) {
        exec.exec { commandLine(command) }
    }

    private companion object {
        val CLANG_ARCH = mapOf("arm64-v8a" to "aarch64", "armeabi-v7a" to "arm", "x86_64" to "x86_64", "x86" to "i686")
    }
}
