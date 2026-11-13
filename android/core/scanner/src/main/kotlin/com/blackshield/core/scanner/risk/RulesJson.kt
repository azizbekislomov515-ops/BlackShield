package com.blackshield.core.scanner.risk

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull

// Strict JSON accessors for the rules file. Each failure names where in the file it happened.

internal fun rulesError(message: String): Nothing = throw RiskRulesException(message)

internal inline fun <reified T : Enum<T>> enumValue(name: String, where: String): T =
    enumValues<T>().firstOrNull { it.name == name } ?: rulesError("$where: unknown value '$name'")

internal fun JsonObject.onlyKeys(allowed: Set<String>, where: String) {
    (keys - allowed).firstOrNull()?.let { rulesError("$where: unknown key '$it'") }
}

internal fun JsonObject.obj(key: String, where: String): JsonObject =
    this[key] as? JsonObject ?: rulesError("$where.$key must be an object")

internal fun JsonObject.array(key: String, where: String): JsonArray =
    this[key] as? JsonArray ?: rulesError("$where.$key must be an array")

internal fun JsonObject.string(key: String, where: String): String =
    (this[key] ?: rulesError("$where.$key is missing")).text("$where.$key")

internal fun JsonObject.int(key: String, where: String): Int =
    (this[key] as? JsonPrimitive)?.takeIf { !it.isString }?.intOrNull ?: rulesError("$where.$key must be an integer")

internal fun JsonElement.text(where: String): String =
    (this as? JsonPrimitive)?.takeIf { it.isString }?.content ?: rulesError("$where must be a string")

internal fun JsonElement.positiveInt(where: String): Int =
    (this as? JsonPrimitive)?.takeIf { !it.isString }?.intOrNull?.takeIf { it > 0 }
        ?: rulesError("$where must be a positive integer")
