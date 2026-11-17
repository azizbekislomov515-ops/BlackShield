package com.blackshield.buildlogic

import javax.inject.Inject
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations
import org.gradle.work.DisableCachingByDefault

/**
 * Builds the module's libFuzzer targets with AddressSanitizer and UndefinedBehaviorSanitizer and runs each one on
 * the connected device for [seconds], starting from the seed corpus in `[corpusDirectory]/<target>/`. Any crash,
 * sanitizer report, timeout or out-of-memory input fails the task; the reproducer is pulled into
 * `[buildDirectory]/findings/`.
 */
@DisableCachingByDefault(because = "Fuzzes on a connected device")
abstract class NativeFuzzTask : DefaultTask() {
    @get:Inject
    abstract val execOperations: ExecOperations

    @get:Internal
    abstract val sourceDirectory: DirectoryProperty

    @get:Internal
    abstract val corpusDirectory: DirectoryProperty

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
    abstract val targets: ListProperty<String>

    /** Run time per target. */
    @get:Input
    abstract val seconds: Property<Int>

    init {
        outputs.upToDateWhen { false }
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
        val binaries = runner.build(
            NativeDeviceRunner.Build(
                source = sourceDirectory.get().asFile,
                buildDir = buildDirectory.get().asFile.resolve(abi),
                abi = abi,
                minSdk = minSdk.get(),
                options = listOf("-DBLACKSHIELD_BUILD_FUZZERS=ON", "-DBLACKSHIELD_SANITIZE=$SANITIZE"),
                targets = targets.get()
            )
        )
        val failed = mutableListOf<String>()
        runner.shell("rm -rf $DEVICE_DIR && mkdir -p $DEVICE_DIR")
        try {
            runner.sanitizerRuntime(SANITIZE, abi)?.let { runner.push(it, "$DEVICE_DIR/${it.name}") }
            binaries.forEach { binary -> if (!fuzz(runner, binary.name, binary)) failed += binary.name }
        } finally {
            runner.shellQuietly("rm -rf $DEVICE_DIR")
        }
        if (failed.isNotEmpty()) {
            val findings = buildDirectory.get().asFile.resolve("findings")
            throw GradleException("Fuzzing found problems in $failed; see $findings")
        }
    }

    /** Returns true if the target ran for the whole time without a finding. */
    private fun fuzz(runner: NativeDeviceRunner, target: String, binary: java.io.File): Boolean {
        val dir = "$DEVICE_DIR/$target"
        runner.shell("mkdir -p $dir/corpus $dir/seeds $dir/findings")
        runner.push(binary, "$dir/$target")
        runner.shell("chmod 755 $dir/$target")
        corpusDirectory.get().asFile.resolve(target).listFiles().orEmpty().filter { it.isFile }.forEach {
            runner.push(it, "$dir/seeds/${it.name}")
        }
        runner.lifecycle("Fuzzing $target for ${seconds.get()} s")
        val status = runner.shellStatus(
            "cd $dir && LD_LIBRARY_PATH=$DEVICE_DIR $SANITIZER_OPTIONS ./$target corpus seeds " +
                "-max_total_time=${seconds.get()} -timeout=$INPUT_TIMEOUT_SECONDS -rss_limit_mb=$RSS_LIMIT_MB " +
                "-max_len=$MAX_LEN -artifact_prefix=findings/ -print_final_stats=1"
        )
        if (status == 0) return true
        val local = buildDirectory.get().asFile.resolve("findings/$target").apply { mkdirs() }
        runner.pull("$dir/findings/.", local)
        return false
    }

    private companion object {
        const val DEVICE_DIR = "/data/local/tmp/blackshield-native-fuzz"
        const val SANITIZE = "address,undefined"
        /**
         * Any sanitizer report is fatal. ASan's periodic release of free memory to the OS is off: on the Android
         * emulator it zeroes allocator metadata of quarantined chunks after tens of thousands of runs, and ASan then
         * stops with a false "CHECK failed ... kAllocBegMagic". Detection does not depend on it.
         */
        const val SANITIZER_OPTIONS =
            "ASAN_OPTIONS=abort_on_error=1:halt_on_error=1:allocator_release_to_os_interval_ms=-1 " +
                "UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1"
        const val INPUT_TIMEOUT_SECONDS = 10
        const val RSS_LIMIT_MB = 2048

        /**
         * libFuzzer's 4 KiB default is too small to reach a DEX file's tables; 64 KiB covers every table the parser
         * walks while keeping executions fast enough (larger seeds are truncated by libFuzzer).
         */
        const val MAX_LEN = 65_536
    }
}
