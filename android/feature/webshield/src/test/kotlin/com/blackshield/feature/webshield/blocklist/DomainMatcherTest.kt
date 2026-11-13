package com.blackshield.feature.webshield.blocklist

import com.blackshield.core.data.model.DomainCategory.MALWARE
import com.blackshield.core.data.model.DomainCategory.PHISHING
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DomainMatcherTest {
    private val matcher =
        DomainMatcher.build(
            listOf(
                "evil.example" to MALWARE,
                "login.bank.example" to PHISHING,
                "Upper.Example." to MALWARE,
                "evil.example" to PHISHING, // duplicate: first wins
                "" to MALWARE,
                "bad..example" to MALWARE
            )
        )

    @Test
    fun `matches the domain and every subdomain`() {
        assertEquals(DomainMatch("evil.example", MALWARE), matcher.match("evil.example"))
        assertEquals(DomainMatch("evil.example", MALWARE), matcher.match("www.evil.example"))
        assertEquals(DomainMatch("evil.example", MALWARE), matcher.match("a.b.c.evil.example."))
        assertEquals(DomainMatch("login.bank.example", PHISHING), matcher.match("x.login.bank.example"))
    }

    @Test
    fun `does not match lookalikes, parents or other suffixes`() {
        listOf("notevil.example", "evil.example.org", "example", "bank.example", "evil-example", "evilexample")
            .forEach { assertNull(it, matcher.match(it)) }
    }

    @Test
    fun `is case-insensitive and ignores the trailing dot`() {
        assertTrue(matcher.contains("WWW.EVIL.EXAMPLE."))
        assertTrue(matcher.contains("upper.example"))
        assertEquals(3, matcher.size)
        assertNull(matcher.match(""))
        assertNull(matcher.match("."))
    }

    @Test
    fun `scales to a large list`() {
        val big = DomainMatcher.build((0 until 200_000).map { "d$it.example${it % 50}.com" to MALWARE })
        assertTrue(big.contains("www.d123456.example6.com"))
        assertFalse(big.contains("d123456.example7.com"))
        val start = System.nanoTime()
        repeat(100_000) { big.match("sub.d$it.example${it % 50}.com") }
        val perLookupMicros = (System.nanoTime() - start) / 100_000 / 1_000.0
        assertTrue("lookup took $perLookupMicros µs", perLookupMicros < 50)
    }

    @Test
    fun `allowlist and temporary allowances win over the blocklist`() {
        var now = 1_000L
        val filter = DnsFilter(TemporaryAllowances { now })
        filter.blocklist = matcher
        assertTrue(filter.decide("www.evil.example") is FilterDecision.Block)
        assertEquals(FilterDecision.Allow, filter.decide("good.example"))

        filter.allowlist = DomainMatcher.build(listOf("bank.example" to PHISHING))
        assertEquals(FilterDecision.Allow, filter.decide("login.bank.example"))

        filter.allowTemporarily("www.evil.example", forMillis = 500)
        assertEquals(FilterDecision.Allow, filter.decide("www.evil.example"))
        assertEquals(FilterDecision.Allow, filter.decide("cdn.www.evil.example"))
        assertTrue("the parent stays blocked", filter.decide("evil.example") is FilterDecision.Block)
        now += 501
        assertTrue("allowance expired", filter.decide("www.evil.example") is FilterDecision.Block)
    }
}
