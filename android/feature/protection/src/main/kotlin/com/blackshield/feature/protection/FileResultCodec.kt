package com.blackshield.feature.protection

import com.blackshield.core.data.model.ScanReason
import com.blackshield.core.data.model.ScanResult
import com.blackshield.core.data.model.Verdict
import com.blackshield.core.scanner.files.FileScanResult
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put

/**
 * A file scan result travels inside the notification's Details intent: files are not installed
 * apps, so they have no row in scan_results, and the intent survives process death.
 */
object FileResultCodec {
    private val json = Json { ignoreUnknownKeys = true }
    private val reasonsSerializer = ListSerializer(ScanReason.serializer())

    fun encode(result: FileScanResult): String {
        val shown = result.asScanResult()
        return buildJsonObject {
            put("package", shown.packageName)
            put("label", shown.appLabel)
            put("sha256", shown.apkSha256)
            put("verdict", shown.verdict.name)
            put("score", shown.riskScore)
            put("scannedAt", shown.scannedAt)
            put("reasons", json.encodeToJsonElement(reasonsSerializer, shown.reasons))
        }.toString()
    }

    /** Null for anything that is not a result this codec wrote. */
    fun decode(text: String?): ScanResult? = text?.let {
        runCatching {
            val obj = json.parseToJsonElement(it) as JsonObject
            ScanResult(
                packageName = obj.getValue("package").jsonPrimitive.content,
                appLabel = obj.getValue("label").jsonPrimitive.content,
                versionCode = 0,
                apkSha256 = (obj["sha256"] as? JsonPrimitive)?.contentOrNull,
                verdict = Verdict.valueOf(obj.getValue("verdict").jsonPrimitive.content),
                riskScore = obj.getValue("score").jsonPrimitive.int,
                reasons = json.decodeFromJsonElement(reasonsSerializer, obj.getValue("reasons")),
                scannedAt = obj.getValue("scannedAt").jsonPrimitive.long
            )
        }.getOrNull()
    }
}
