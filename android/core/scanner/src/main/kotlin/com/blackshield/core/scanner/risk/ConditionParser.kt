package com.blackshield.core.scanner.risk

import com.blackshield.core.scanner.analysis.LauncherState
import com.blackshield.core.scanner.yara.YaraSeverity
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull

/** Parses a rule's `when`: an object with exactly one key, the condition type. */
internal class ConditionParser(private val lists: Map<String, List<String>>) {
    // One branch per condition type: the vocabulary reads best as a single table.
    @Suppress("CyclomaticComplexMethod")
    fun parse(element: JsonElement, where: String, depth: Int = 0): Condition {
        if (depth > MAX_DEPTH) rulesError("$where: conditions nested deeper than $MAX_DEPTH")
        val obj = element as? JsonObject ?: rulesError("$where must be an object")
        if (obj.size != 1) rulesError("$where must have exactly one key, the condition type")
        val (type, arg) = obj.entries.single()
        val at = "$where.$type"
        return when (type) {
            "all" -> Condition.All(children(arg, at, depth))
            "any" -> Condition.AnyOf(children(arg, at, depth))
            "not" -> Condition.Not(parse(arg, at, depth + 1))
            "requestsPermission" -> Condition.RequestsPermissions(listOf(arg.text(at)), requireAll = true)
            "requestsAllPermissions" -> Condition.RequestsPermissions(strings(arg, at), requireAll = true)
            "requestsAnyPermission" -> Condition.RequestsPermissions(strings(arg, at), requireAll = false)
            "dangerousPermissionsAtLeast" -> Condition.DangerousPermissionsAtLeast(arg.positiveInt(at))
            "installSource" -> Condition.FromSource(enums<InstallSource>(arg, at))
            "componentWithPermission" -> Condition.ComponentWithPermission(arg.text(at))
            "handlesAction" -> Condition.HandlesAction(strings(arg, at))
            "launcher" -> Condition.Launcher(enums<LauncherState>(arg, at))
            "installedWithinDays" -> Condition.InstalledWithinDays(arg.positiveInt(at))
            "targetSdkBelow" -> Condition.TargetSdkBelow(arg.positiveInt(at))
            "certificate" -> Condition.Certificate(enumValue(arg.text(at), at))
            "applicationClassIn" -> Condition.ApplicationClassIn(strings(arg, at))
            "nativeLibraryMatches" -> Condition.NativeLibraryMatches(strings(arg, at))
            "obfuscatedComponents" -> obfuscated(arg, at)
            "yaraMatch" -> Condition.PatternMatch(enums<YaraSeverity>(arg, at))
            "accessibilityEnabled" -> flag(arg, at, Condition.AccessibilityEnabled)
            "deviceAdminActive" -> flag(arg, at, Condition.DeviceAdminActive)
            "debuggable" -> flag(arg, at, Condition.Debuggable)
            else -> rulesError("$where: unknown condition '$type'")
        }
    }

    private fun children(arg: JsonElement, where: String, depth: Int): List<Condition> {
        val array = arg as? JsonArray ?: rulesError("$where must be an array")
        if (array.isEmpty()) rulesError("$where is empty")
        return array.mapIndexed { i, child -> parse(child, "$where[$i]", depth + 1) }
    }

    /** A string, an array of strings, or "@name" referring to `lists`. */
    private fun strings(arg: JsonElement, where: String): List<String> {
        val raw = if (arg is JsonArray) {
            arg.mapIndexed { i, item ->
                item.text("$where[$i]")
            }
        } else {
            listOf(arg.text(where))
        }
        val values = raw.flatMap { value -> if (value.startsWith("@")) listReference(value, where) else listOf(value) }
        if (values.isEmpty()) rulesError("$where is empty")
        return values
    }

    private fun listReference(value: String, where: String): List<String> =
        lists[value.drop(1)] ?: rulesError("$where: unknown list '$value'")

    private inline fun <reified T : Enum<T>> enums(arg: JsonElement, where: String): Set<T> =
        strings(arg, where).mapTo(LinkedHashSet()) { enumValue<T>(it, where) }

    private fun obfuscated(arg: JsonElement, where: String): Condition {
        val obj = arg as? JsonObject ?: rulesError("$where must be an object")
        obj.onlyKeys(setOf("minComponents", "minShare"), where)
        val share = (obj["minShare"] as? JsonPrimitive)?.doubleOrNull ?: rulesError("$where.minShare must be a number")
        if (share <= 0.0 || share > 1.0) rulesError("$where.minShare must be in (0, 1]")
        return Condition.ObfuscatedComponents(obj.int("minComponents", where).coerceAtLeast(1), share)
    }

    private fun flag(arg: JsonElement, where: String, condition: Condition): Condition {
        if ((arg as? JsonPrimitive)?.booleanOrNull != true) rulesError("$where must be true (use \"not\" to negate)")
        return condition
    }

    private companion object {
        const val MAX_DEPTH = 16
    }
}
