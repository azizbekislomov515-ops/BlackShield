package com.blackshield.core.scanner.yara

import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import timber.log.Timber

/** The ruleset in use. */
data class ActiveRuleset(
    val version: Long,
    val sha256: String,
    val source: Source,
    val ruleCount: Int,
    /** Why a stored update was not used (tampered, did not compile...), if one was rejected. */
    val rejectedUpdate: String? = null
) {
    enum class Source { BUNDLED, UPDATE }
}

sealed interface RulesInstallResult {
    data class Installed(val version: Long) : RulesInstallResult

    /** Not newer than the rules in use: a replay or rollback, or simply nothing new. */
    data class NotNewer(val version: Long, val activeVersion: Long) : RulesInstallResult

    data class Rejected(val reason: String) : RulesInstallResult
}

/** What the backend sync needs: the version in use, and a way to hand over a downloaded ruleset. */
interface YaraRulesInstaller {
    fun activeVersion(): Long

    /** Verifies [signedJson] (the `GET /v1/rules` body) and, if it is valid and newer, switches to it. */
    fun install(signedJson: String): RulesInstallResult
}

/**
 * Owns the active YARA ruleset: the one bundled in the APK (assets/yara/bundled.yar), or a newer
 * signed update from the backend stored at `<directory>/ruleset.json`.
 *
 * Updates are verified ([RulesetVerifier]) when they arrive and again every time they are loaded,
 * so a stored file changed on disk is rejected (and deleted) and the bundled rules are used. An
 * update must be newer than both the bundled and the current rules (no rollback), and must compile
 * before it replaces the working rules. A new ruleset takes effect for the next scan: no app
 * update or restart is needed.
 */
class YaraRules internal constructor(
    private val directory: File,
    private val bundledSource: () -> String,
    private val verifier: RulesetVerifier,
    private val compiler: (String) -> YaraCompileResult
) : YaraRulesInstaller {
    private class Loaded(val active: ActiveRuleset, val scanner: YaraScanner?)

    private val lock = Any()

    @Volatile
    private var loaded: Loaded? = null

    private val storage = RulesetFile(File(directory, UPDATE_FILE))

    /** The active ruleset, loading (and compiling) it on first use. */
    fun active(): ActiveRuleset = current().active

    override fun activeVersion(): Long = active().version

    /**
     * Runs [block] with the compiled active rules; null when no rules could be compiled. If the
     * rules are replaced meanwhile, the old ones stay alive until [block] returns.
     */
    fun <T : Any> withScanner(block: (YaraScanner, ActiveRuleset) -> T): T? {
        var result: T? = null
        var attempts = 0
        while (result == null && attempts++ < ATTEMPTS) {
            val state = current()
            val scanner = state.scanner ?: break
            result = scanner.borrow { block(scanner, state.active) } // null: replaced just now, retry
        }
        return result
    }

    override fun install(signedJson: String): RulesInstallResult = synchronized(lock) {
        val verified =
            try {
                verifier.verify(signedJson)
            } catch (e: RulesetRejectedException) {
                return RulesInstallResult.Rejected(e.message.orEmpty())
            }
        val active = current().active
        if (verified.version <= active.version) return RulesInstallResult.NotNewer(verified.version, active.version)
        val scanner =
            when (val compiled = compiler(verified.rules)) {
                is YaraCompileResult.Success -> compiled.scanner

                is YaraCompileResult.Failure ->
                    return RulesInstallResult.Rejected("rules do not compile: ${compiled.errors.take(ERRORS_SHOWN)}")
            }
        if (!storage.write(signedJson)) {
            scanner.close()
            return RulesInstallResult.Rejected("could not store the rules")
        }
        replace(
            Loaded(
                ActiveRuleset(verified.version, verified.sha256, ActiveRuleset.Source.UPDATE, scanner.ruleCount),
                scanner
            )
        )
        Timber.i("YARA rules updated to version %d", verified.version)
        RulesInstallResult.Installed(verified.version)
    }

    /** Drops the compiled rules; the next scan loads (and re-verifies) them from disk. */
    fun reload() = synchronized(lock) { replace(null) }

    private fun current(): Loaded = loaded ?: synchronized(lock) { loaded ?: load().also { loaded = it } }

    private fun replace(next: Loaded?) {
        val previous = loaded
        loaded = next
        if (previous?.scanner !== next?.scanner) previous?.scanner?.close() // In-flight scans keep it alive.
    }

    /** What became of the stored update: loaded, rejected (with why), or neither (none, or not newer). */
    private class UpdateOutcome(val loaded: Loaded? = null, val rejected: String? = null)

    private fun loadUpdate(bundledVersion: Long): UpdateOutcome {
        val stored = storage.read() ?: return UpdateOutcome()
        return try {
            val update = verifier.verify(stored)
            // The app may ship newer bundled rules than an update stored before it was updated.
            if (update.version > bundledVersion) compileUpdate(update) else UpdateOutcome()
        } catch (e: RulesetRejectedException) {
            storage.delete()
            UpdateOutcome(rejected = "stored update rejected: ${e.message}")
        }
    }

    private fun compileUpdate(update: VerifiedRuleset): UpdateOutcome = when (val compiled = compiler(update.rules)) {
        is YaraCompileResult.Success -> UpdateOutcome(
            Loaded(
                ActiveRuleset(update.version, update.sha256, ActiveRuleset.Source.UPDATE, compiled.scanner.ruleCount),
                compiled.scanner
            )
        )

        is YaraCompileResult.Failure -> UpdateOutcome(rejected = "update ${update.version} does not compile")
    }

    private fun load(): Loaded {
        val bundled = bundledSource()
        val bundledVersion = bundledVersion(bundled)
        val update = loadUpdate(bundledVersion)
        update.loaded?.let { return it }
        val rejected = update.rejected
        rejected?.let { Timber.w("YARA %s; using the bundled rules", it) }
        val sha256 = RulesetVerifier.sha256Hex(bundled.toByteArray(Charsets.UTF_8))
        return when (val compiled = compiler(bundled)) {
            is YaraCompileResult.Success -> Loaded(
                ActiveRuleset(
                    bundledVersion,
                    sha256,
                    ActiveRuleset.Source.BUNDLED,
                    compiled.scanner.ruleCount,
                    rejected
                ),
                compiled.scanner
            )

            is YaraCompileResult.Failure -> {
                Timber.e("Bundled YARA rules do not compile: %s", compiled.errors)
                Loaded(ActiveRuleset(bundledVersion, sha256, ActiveRuleset.Source.BUNDLED, 0, rejected), null)
            }
        }
    }

    companion object {
        const val UPDATE_FILE = "ruleset.json"
        private const val ATTEMPTS = 3
        private const val ERRORS_SHOWN = 3
        private val VERSION_HEADER = Regex("^// blackshield-yara-rules version: (\\d+)\\s*$", RegexOption.MULTILINE)

        /** The version in the bundled file's `// blackshield-yara-rules version: N` header; 0 without one. */
        fun bundledVersion(source: String): Long =
            VERSION_HEADER.find(source)?.groupValues?.get(1)?.toLongOrNull() ?: 0L
    }
}

/** The stored signed ruleset, replaced atomically so a crash never leaves half a file. */
internal class RulesetFile(private val file: File) {
    fun read(): String? = try {
        file.takeIf { it.isFile }?.readText(Charsets.UTF_8)
    } catch (e: IOException) {
        Timber.w(e, "Could not read the stored YARA rules")
        null
    }

    fun write(json: String): Boolean {
        file.parentFile?.mkdirs()
        val temp = File(file.path + ".tmp")
        return try {
            temp.outputStream().use { out ->
                out.write(json.toByteArray(Charsets.UTF_8))
                out.fd.sync()
            }
            Files.move(
                temp.toPath(),
                file.toPath(),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING
            )
            true
        } catch (e: IOException) {
            Timber.w(e, "Could not store the YARA rules")
            false
        } finally {
            temp.delete()
        }
    }

    fun delete() {
        file.delete()
    }
}
