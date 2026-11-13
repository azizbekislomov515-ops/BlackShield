package com.blackshield.core.scanner.risk

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton
import timber.log.Timber

/** Supplies the active risk rules. */
fun interface RiskRulesSource {
    fun rules(): RiskRules
}

object RiskRulesLoader {
    /**
     * Rules from [override] (a downloaded update) when it parses, otherwise from [bundled] (shipped
     * with the app, always valid: a unit test parses it). A bad update never disables scanning.
     */
    fun load(override: String?, bundled: String, onRejected: (RiskRulesException) -> Unit = {}): RiskRules {
        if (override != null) {
            try {
                return RiskRulesParser.parse(override)
            } catch (e: RiskRulesException) {
                onRejected(e)
            }
        }
        return RiskRulesParser.parse(bundled)
    }
}

/**
 * Bundled rules (assets/risk/risk_rules.json), or a newer copy at
 * `noBackupFilesDir/risk/risk_rules.json` where a future backend download will put it. Read once
 * per process.
 */
@Singleton
internal class BundledRiskRulesSource
@Inject
constructor(@ApplicationContext private val context: Context) :
    RiskRulesSource {
    private val rules: RiskRules by lazy {
        val override = File(context.noBackupFilesDir, OVERRIDE_PATH)
        val overrideText =
            try {
                override.takeIf { it.isFile }?.readText()
            } catch (e: IOException) {
                Timber.w(e, "Could not read %s", OVERRIDE_PATH)
                null
            }
        val bundled = context.assets.open(ASSET_PATH).bufferedReader().use { it.readText() }
        RiskRulesLoader.load(overrideText, bundled) { Timber.w(it, "Ignoring invalid risk rules update") }
            .also { Timber.i("Risk rules %s (%d rules)", it.rulesVersion, it.rules.size) }
    }

    override fun rules(): RiskRules = rules

    private companion object {
        const val ASSET_PATH = "risk/risk_rules.json"
        const val OVERRIDE_PATH = "risk/risk_rules.json"
    }
}
