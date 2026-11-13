package com.blackshield.feature.webshield.blocklist

import com.blackshield.core.data.model.DomainCategory

/** Which listed domain matched a lookup, and why it is listed. */
data class DomainMatch(val listed: String, val category: DomainCategory)

/**
 * Domain lookup with subdomain matching: listing `evil.example` also matches `www.evil.example`
 * and `a.b.evil.example`, never `notevil.example` or `evil.example.org`.
 *
 * It is a label trie stored flat: every domain is keyed by its labels in reverse order
 * (`example.evil`), and the keys are sorted, so a trie path is a key and its children follow it.
 * A lookup tests each label-boundary prefix of the reversed query (`example`, `example.evil`,
 * `example.evil.www`) by binary search: at most one search per label, O(labels x log n), with one
 * String per listed domain and no per-node objects, which keeps 100k+ domains at a few MiB.
 * Immutable and safe to share between threads; rebuilt when the list changes.
 */
class DomainMatcher private constructor(
    private val keys: Array<String>,
    private val categories: Array<DomainCategory>
) {
    val size: Int get() = keys.size

    fun match(domain: String): DomainMatch? {
        val labels = normalize(domain)?.split('.') ?: return null
        val prefix = StringBuilder()
        var found: DomainMatch? = null
        var i = labels.size - 1
        while (found == null && i >= 0) {
            if (prefix.isNotEmpty()) prefix.append('.')
            prefix.append(labels[i])
            val index = keys.binarySearch(prefix.toString())
            if (index >= 0) found = DomainMatch(labels.subList(i, labels.size).joinToString("."), categories[index])
            i--
        }
        return found
    }

    fun contains(domain: String): Boolean = match(domain) != null

    companion object {
        val EMPTY = DomainMatcher(emptyArray(), emptyArray())

        fun build(entries: Collection<Pair<String, DomainCategory>>): DomainMatcher {
            val sorted =
                entries
                    .mapNotNull { (domain, category) -> normalize(domain)?.let { reverse(it) to category } }
                    .sortedBy { it.first }
                    .distinctBy { it.first }
            return DomainMatcher(
                sorted.map { it.first }.toTypedArray(),
                sorted.map { it.second }.toTypedArray()
            )
        }

        /** Lower case, no trailing dot, no empty labels; null if nothing is left. */
        fun normalize(domain: String): String? = domain
            .trim()
            .trimEnd('.')
            .lowercase()
            .takeIf { it.isNotEmpty() && ".." !in it && !it.startsWith('.') }

        private fun reverse(domain: String): String = domain.split('.').asReversed().joinToString(".")
    }
}
