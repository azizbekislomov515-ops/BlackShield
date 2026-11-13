package com.blackshield.core.scanner.risk

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull

/** The rules file is invalid; the message says where. Nothing from it is used. */
class RiskRulesException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Strict parser for the rules JSON: an unknown key, condition type or list reference rejects the
 * whole file, so a rules update meant for a newer app can never be half-applied. The caller then
 * keeps the rules it already has.
 */
object RiskRulesParser {
    internal const val MAX_POINTS = 100
    private val RULE_ID = Regex("^[a-z0-9_]{1,64}$")

    private val TOP_LEVEL_KEYS =
        setOf(
            "schemaVersion",
            "rulesVersion",
            "thresholds",
            "trustedInstallers",
            "allowlist",
            "lists",
            "groups",
            "rules"
        )

    fun parse(json: String): RiskRules {
        val root =
            try {
                Json.parseToJsonElement(json)
            } catch (e: SerializationException) {
                throw RiskRulesException("not valid JSON", e)
            } as? JsonObject ?: rulesError("the top level must be an object")
        root.onlyKeys(TOP_LEVEL_KEYS, "top level")

        val schema = root.int("schemaVersion", "top level")
        if (schema !=
            RiskRules.SCHEMA_VERSION
        ) {
            rulesError("unsupported schemaVersion $schema (supported: ${RiskRules.SCHEMA_VERSION})")
        }
        val lists = parseLists(root["lists"])
        val groups = parseGroups(root["groups"])
        val rules = root.array("rules", "top level").mapIndexed { i, rule ->
            parseRule(rule, "rules[$i]", lists, groups)
        }
        rules.groupBy {
            it.id
        }.filterValues { it.size > 1 }.keys.firstOrNull()?.let { rulesError("duplicate rule id '$it'") }

        return RiskRules(
            schemaVersion = schema,
            rulesVersion = root.string("rulesVersion", "top level"),
            thresholds = parseThresholds(root.obj("thresholds", "top level")),
            trustedInstallers =
                root.obj("trustedInstallers", "top level").mapValues { (key, value) ->
                    value.text("trustedInstallers.$key")
                },
            exemptSystemApps = parseAllowlist(root["allowlist"]).first,
            knownGood = parseAllowlist(root["allowlist"]).second,
            groupCaps = groups,
            rules = rules
        )
    }

    private fun parseThresholds(obj: JsonObject): Thresholds {
        obj.onlyKeys(setOf("suspicious", "malicious"), "thresholds")
        val thresholds = Thresholds(obj.int("suspicious", "thresholds"), obj.int("malicious", "thresholds"))
        if (thresholds.suspicious !in 1 until thresholds.malicious || thresholds.malicious > MAX_POINTS) {
            rulesError("thresholds must satisfy 0 < suspicious < malicious <= $MAX_POINTS")
        }
        return thresholds
    }

    private fun parseAllowlist(element: JsonElement?): Pair<Boolean, List<KnownGoodApp>> {
        val obj = element as? JsonObject ?: return true to emptyList()
        obj.onlyKeys(setOf("systemApps", "apps"), "allowlist")
        val systemApps =
            obj["systemApps"]?.let {
                (it as? JsonPrimitive)?.booleanOrNull
                    ?: rulesError("allowlist.systemApps must be a boolean")
            }
                ?: true
        val apps =
            (obj["apps"] as? JsonArray).orEmpty().mapIndexed { i, app ->
                val where = "allowlist.apps[$i]"
                val o = app as? JsonObject ?: rulesError("$where must be an object")
                o.onlyKeys(setOf("package", "certSha256"), where)
                val cert = o.string("certSha256", where).lowercase()
                if (!cert.matches(Regex("^[0-9a-f]{64}$"))) rulesError("$where.certSha256 must be 64 hex digits")
                KnownGoodApp(o.string("package", where), cert)
            }
        return systemApps to apps
    }

    private fun parseLists(element: JsonElement?): Map<String, List<String>> {
        val obj = element as? JsonObject ?: return emptyMap()
        return obj.mapValues { (name, value) ->
            (value as? JsonArray ?: rulesError("lists.$name must be an array")).mapIndexed { i, item ->
                item.text("lists.$name[$i]")
            }
        }
    }

    private fun parseGroups(element: JsonElement?): Map<String, Int> {
        val obj = element as? JsonObject ?: return emptyMap()
        return obj.mapValues { (name, value) ->
            val group = value as? JsonObject ?: rulesError("groups.$name must be an object")
            group.onlyKeys(setOf("maxPoints"), "groups.$name")
            group.int("maxPoints", "groups.$name").also {
                if (it !in
                    1..MAX_POINTS
                ) {
                    rulesError("groups.$name.maxPoints must be 1..$MAX_POINTS")
                }
            }
        }
    }

    private fun parseRule(
        element: JsonElement,
        where: String,
        lists: Map<String, List<String>>,
        groups: Map<String, Int>
    ): Rule {
        val obj = element as? JsonObject ?: rulesError("$where must be an object")
        obj.onlyKeys(setOf("id", "title", "points", "group", "when"), where)
        val id = obj.string("id", where)
        if (!RULE_ID.matches(id)) rulesError("$where.id must match ${RULE_ID.pattern}")
        val points = obj.int("points", where)
        if (points !in -MAX_POINTS..MAX_POINTS) rulesError("$where.points must be within ±$MAX_POINTS")
        val title = obj.string("title", where).trim()
        if (title.isEmpty()) rulesError("$where.title is empty")
        val group = obj["group"]?.text("$where.group")?.also {
            if (it !in
                groups
            ) {
                rulesError("$where.group: unknown group '$it'")
            }
        }
        val condition = ConditionParser(
            lists
        ).parse(obj["when"] ?: rulesError("$where.when is missing"), "$where.when", 0)
        return Rule(id, title, points, condition, group)
    }
}
