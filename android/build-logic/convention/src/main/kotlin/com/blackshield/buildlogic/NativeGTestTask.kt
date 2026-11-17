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
 * Cross-compiles the GoogleTest suite of a native module with the NDK's CMake toolchain, optionally with
 * sanitizers ([sanitize]: "address", "undefined" or "address,undefined"), pushes it to the connected device
 * (honours ANDROID_SERIAL) and runs it there. The task fails if any test fails or a sanitizer reports an error.
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

    /** Empty for a plain build. */
    @get:Input
    abstract val sanitize: Property<String>

    init {
        outputs.upToDateWhen { false }
        sanitize.convention("")
    }

    @TaskAction
    fun run() {
        val runner = NativeDeviceRunner(
            execOperations,
            logger,
            sdkDirectory.get().asFile,
            ndkVersion.get(),
            cmakeVersion.get()
        )
        val abi = abi.get()
        val sanitize = sanitize.get()
        val variant = if (sanitize.isEmpty()) abi else "$abi-${sanitize.replace(',', '-')}"
        runner.lifecycle("Building native tests from ${testSourceDirectory.get().asFile} for $variant")
        val binary = runner.build(
            NativeDeviceRunner.Build(
                source = sourceDirectory.get().asFile,
                buildDir = buildDirectory.get().asFile.resolve(variant),
                abi = abi,
                minSdk = minSdk.get(),
                options = listOf("-DBLACKSHIELD_BUILD_TESTS=ON", "-DBLACKSHIELD_SANITIZE=$sanitize"),
                targets = listOf(TEST_BINARY)
            )
        ).single()

        runner.shell("rm -rf $DEVICE_DIR && mkdir -p $DEVICE_DIR")
        try {
            runner.push(binary, "$DEVICE_DIR/$TEST_BINARY")
            runner.sanitizerRuntime(sanitize, abi)?.let { runner.push(it, "$DEVICE_DIR/${it.name}") }
            runner.shell("chmod 755 $DEVICE_DIR/$TEST_BINARY")
            runner.shell(
                "cd $DEVICE_DIR && TMPDIR=$DEVICE_DIR LD_LIBRARY_PATH=$DEVICE_DIR $SANITIZER_OPTIONS " +
                    "./$TEST_BINARY --gtest_color=no --gtest_filter='${gtestFilter.get()}'"
            )
        } finally {
            runner.shellQuietly("rm -rf $DEVICE_DIR")
        }
    }

    private companion object {
        const val TEST_BINARY = "blackshield_scanner_tests"
        const val DEVICE_DIR = "/data/local/tmp/blackshield-native-tests"

        /**
         * Any sanitizer report is fatal. ASan's periodic release of free memory to the OS is off: on the Android
         * emulator it zeroes allocator metadata of quarantined chunks after tens of thousands of runs, and ASan then
         * stops with a false "CHECK failed ... kAllocBegMagic". Detection does not depend on it.
         */
        const val SANITIZER_OPTIONS =
            "ASAN_OPTIONS=abort_on_error=1:halt_on_error=1:allocator_release_to_os_interval_ms=-1 " +
                "UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1"
    }
}
