package com.blackshield.buildlogic

import javax.inject.Inject
import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations
import org.gradle.work.DisableCachingByDefault

/**
 * Cross-compiles the GoogleTest suite of a native module with the NDK's CMake toolchain,
 * pushes the binary to the connected device (honours ANDROID_SERIAL) and runs it there.
 * The task fails if any test fails.
 */
@DisableCachingByDefault(because = "Runs tests on a connected device")
abstract class NativeGTestTask : DefaultTask() {
    @get:Inject
    abstract val execOperations: ExecOperations

    /** Directory with the module's top-level CMakeLists.txt. */
    @get:Internal
    abstract val sourceDirectory: DirectoryProperty

    /** Directory with the GoogleTest sources (only used to report what is being run). */
    @get:Internal
    abstract val testSourceDirectory: DirectoryProperty

    @get:Internal
    abstract val buildDirectory: DirectoryProperty

    @get:Internal
    abstract val sdkDirectory: DirectoryProperty

    @get:Input
    abstract val ndkVersion: Property<String>

    @get:Input
    abstract val cmakeVersion: Property<String>

    @get:Input
    abstract val abi: Property<String>

    @get:Input
    abstract val minSdk: Property<Int>

    @get:Input
    abstract val gtestFilter: Property<String>

    init {
        outputs.upToDateWhen { false }
    }

    @TaskAction
    fun run() {
        val sdk = sdkDirectory.get().asFile
        val exe = if (System.getProperty("os.name").startsWith("Windows")) ".exe" else ""
        val cmakeBin = sdk.resolve("cmake/${cmakeVersion.get()}/bin")
        val cmake = cmakeBin.resolve("cmake$exe")
        val ninja = cmakeBin.resolve("ninja$exe")
        val ndk = sdk.resolve("ndk/${ndkVersion.get()}")
        val adb = sdk.resolve("platform-tools/adb$exe")
        listOf(cmake, ninja, ndk, adb).forEach {
            require(it.exists()) { "Missing $it (install it with the SDK manager)" }
        }

        val abi = abi.get()
        val buildDir = buildDirectory.get().asFile.resolve(abi)
        logger.lifecycle("Building native tests from ${testSourceDirectory.get().asFile} for $abi")

        run(
            cmake.path,
            "-S", sourceDirectory.get().asFile.path,
            "-B", buildDir.path,
            "-G", "Ninja",
            "-DCMAKE_MAKE_PROGRAM=${ninja.path}",
            "-DCMAKE_TOOLCHAIN_FILE=${ndk.resolve("build/cmake/android.toolchain.cmake").path}",
            "-DANDROID_ABI=$abi",
            "-DANDROID_PLATFORM=android-${minSdk.get()}",
            "-DANDROID_STL=c++_static",
            "-DCMAKE_BUILD_TYPE=Release",
            "-DBLACKSHIELD_BUILD_TESTS=ON",
        )
        run(cmake.path, "--build", buildDir.path, "--target", TEST_BINARY)

        val binary = buildDir.walkTopDown().first { it.isFile && it.name == TEST_BINARY }
        val deviceBinary = "$DEVICE_DIR/$TEST_BINARY"
        run(adb.path, "shell", "rm -rf $DEVICE_DIR && mkdir -p $DEVICE_DIR")
        try {
            run(adb.path, "push", binary.path, deviceBinary)
            run(adb.path, "shell", "chmod 755 $deviceBinary")
            run(
                adb.path,
                "shell",
                "cd $DEVICE_DIR && TMPDIR=$DEVICE_DIR ./$TEST_BINARY --gtest_color=no " +
                    "--gtest_filter='${gtestFilter.get()}'",
            )
        } finally {
            execOperations.exec {
                commandLine(adb.path, "shell", "rm -rf $DEVICE_DIR")
                isIgnoreExitValue = true
            }
        }
    }

    private fun run(vararg command: String) {
        execOperations.exec { commandLine(*command) }
    }

    private companion object {
        const val TEST_BINARY = "blackshield_scanner_tests"
        const val DEVICE_DIR = "/data/local/tmp/blackshield-native-tests"
    }
}
