package com.blackshield.feature.webshield.blocklist

import java.util.concurrent.ConcurrentHashMap

/** What to do with one lookup. */
sealed interface FilterDecision {
    data object Allow : FilterDecision

    data class Block(val match: DomainMatch) : FilterDecision
}

/**
 * Domains allowed for a limited time ("Allow once" on a blocked-page notification), each with its
 * subdomains. In memory only: a restart forgets them, which is the safe direction.
 */
class TemporaryAllowances(private val now: () -> Long = System::currentTimeMillis) {
    private val until = ConcurrentHashMap<String, Long>()

    fun allow(domain: String, forMillis: Long) {
        DomainMatcher.normalize(domain)?.let { until[it] = now() + forMillis }
    }

    fun isAllowed(domain: String): Boolean {
        val name = DomainMatcher.normalize(domain) ?: return false
        val time = now()
        until.entries.removeIf { it.value <= time }
        return generateSequence(name) { suffix -> suffix.substringAfter('.', "").takeIf { it.contains('.') } }
            .any { until.containsKey(it) }
    }
}

/**
 * The decision for a lookup: the user's allowlist and temporary allowances win over the
 * blocklist, matching with subdomains in both cases. The matchers are swapped atomically when
 * the lists change, so a lookup always sees one consistent version of each.
 */
class DnsFilter(private val temporary: TemporaryAllowances = TemporaryAllowances()) {
    @Volatile
    var blocklist: DomainMatcher = DomainMatcher.EMPTY

    @Volatile
    var allowlist: DomainMatcher = DomainMatcher.EMPTY

    fun decide(name: String): FilterDecision {
        val match = blocklist.match(name)
        val allowed = match == null || allowlist.contains(name) || temporary.isAllowed(name)
        return if (allowed || match == null) FilterDecision.Allow else FilterDecision.Block(match)
    }

    fun allowTemporarily(domain: String, forMillis: Long) = temporary.allow(domain, forMillis)
}
