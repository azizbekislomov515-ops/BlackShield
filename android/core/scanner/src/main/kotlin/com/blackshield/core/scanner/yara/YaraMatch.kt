package com.blackshield.core.scanner.yara

/** How bad a match is, from the rule's `severity` meta field. Rules without one count as [MEDIUM]. */
enum class YaraSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    companion object {
        fun of(value: String?): YaraSeverity = entries.firstOrNull { it.name.equals(value?.trim(), ignoreCase = true) }
            ?: MEDIUM
    }
}

/** One YARA rule that matched. */
data class YaraMatch(
    val rule: String,
    val namespace: String = "default",
    val tags: List<String> = emptyList(),
    /** The rule's `meta:` section; integers in decimal, booleans as "true"/"false". */
    val meta: Map<String, String> = emptyMap(),
    /** Where it matched: the scanned file's name, or the archive entry (e.g. `classes2.dex`). */
    val location: String = ""
) {
    val severity: YaraSeverity get() = YaraSeverity.of(meta["severity"])

    /** The rule's `description` meta field, if any. */
    val description: String? get() = meta["description"]?.takeIf { it.isNotBlank() }
}

/** Status codes; the ordinals must match blackshield::yara::YaraStatus. */
enum class YaraStatus {
    OK,
    TIMEOUT,
    COMPILE_ERROR,
    FILE_ERROR,
    INVALID_ARGUMENT,
    INTERNAL_ERROR;

    companion object {
        fun of(code: Long): YaraStatus = entries.getOrNull(code.toInt()) ?: INTERNAL_ERROR
    }
}

/** Matches from one file, plus everything that could not be scanned (timeouts, unreadable entries). */
data class YaraScanReport(val matches: List<YaraMatch>, val problems: List<String> = emptyList())

/** Decodes the flattened JNI result (see [YaraBridge]). Malformed input ends the list early. */
internal object YaraMatches {
    /** rule, namespace, tag count. */
    private const val HEADER_FIELDS = 3
    private const val TAG_COUNT = 2

    /** key, type, value. */
    private const val META_FIELDS = 3
    private const val META_VALUE = 2

    fun parse(flat: Array<String>, location: String): List<YaraMatch> {
        val matches = mutableListOf<YaraMatch>()
        var next: Pair<YaraMatch, Int>? = parseOne(flat, 0, location)
        while (next != null) {
            matches += next.first
            next = parseOne(flat, next.second, location)
        }
        return matches
    }

    /** The match starting at [start] and where the next one starts; null at the end or on bad input. */
    private fun parseOne(flat: Array<String>, start: Int, location: String): Pair<YaraMatch, Int>? {
        val tagCount = flat.getOrNull(start + TAG_COUNT)?.toIntOrNull()?.takeIf { it >= 0 } ?: return null
        // Long arithmetic: counts come from native code and must not overflow into a valid-looking index.
        val metaAt = start.toLong() + HEADER_FIELDS + tagCount
        val metaCount =
            flat.getOrNull(metaAt.toInt().takeIf { metaAt < flat.size } ?: -1)?.toIntOrNull()?.takeIf {
                it >= 0 && metaAt + 1 + it.toLong() * META_FIELDS <= flat.size
            }
        return metaCount?.let { count ->
            val at = metaAt.toInt()
            val meta = LinkedHashMap<String, String>()
            for (m in 0 until count) {
                val key = at + 1 + m * META_FIELDS
                meta.putIfAbsent(flat[key], flat[key + META_VALUE]) // the type sits in between; values are text
            }
            val match =
                YaraMatch(
                    flat[start],
                    flat[start + 1],
                    flat.copyOfRange(start + HEADER_FIELDS, at).toList(),
                    meta,
                    location
                )
            match to at + 1 + count * META_FIELDS
        }
    }
}
