// DNS header layout, flags and record types are fixed by RFC 1035/3596. Parsing is a sequence of
// guard clauses: one early return (or branch) per malformed case.
@file:Suppress("MagicNumber", "ReturnCount", "CyclomaticComplexMethod")

package com.blackshield.feature.webshield.dns

import com.blackshield.feature.webshield.dns.IpPackets.put16
import com.blackshield.feature.webshield.dns.IpPackets.u16

/** The single question of a standard query. [name] is lower case, without the trailing dot. */
data class DnsQuestion(val name: String, val type: Int, val dnsClass: Int)

/** A parsed query; [questionEnd] is where the question section ends in [raw]. */
class DnsQuery(val id: Int, val flags: Int, val question: DnsQuestion, val questionEnd: Int, val raw: ByteArray) {
    val recursionDesired: Boolean get() = flags and FLAG_RD != 0

    private companion object {
        const val FLAG_RD = 0x0100
    }
}

sealed interface DnsParse {
    data class Query(val query: DnsQuery) : DnsParse

    /** Well-formed header but not something to filter (not a query, not one question): refuse with this rcode. */
    data class Refuse(val id: Int, val rcode: Int) : DnsParse

    /** Too broken to answer at all; drop it. */
    data object Malformed : DnsParse
}

/**
 * DNS message parsing and the few responses Web Shield builds itself (RFC 1035, 2308, 3596).
 * Queries the filter allows are forwarded byte for byte, so only the question is parsed.
 */
object DnsMessages {
    const val TYPE_A = 1
    const val TYPE_AAAA = 28
    const val CLASS_IN = 1
    const val RCODE_FORMERR = 1
    const val RCODE_SERVFAIL = 2
    const val RCODE_NXDOMAIN = 3
    const val RCODE_NOTIMP = 4

    private const val HEADER = 12
    private const val MAX_NAME = 255
    private const val MAX_LABEL = 63
    private const val MAX_POINTERS = 16
    private const val FLAG_QR = 0x8000
    private const val FLAG_RA = 0x0080
    private const val OPCODE_MASK = 0x7800
    private const val RD_MASK = 0x0100

    fun parse(message: ByteArray): DnsParse {
        if (message.size < HEADER) return DnsParse.Malformed
        val id = u16(message, 0)
        val flags = u16(message, 2)
        if (flags and FLAG_QR != 0) return DnsParse.Malformed // a response sent to us: ignore
        if (flags and OPCODE_MASK != 0) return DnsParse.Refuse(id, RCODE_NOTIMP) // only QUERY
        if (u16(message, 4) != 1) return DnsParse.Refuse(id, RCODE_FORMERR) // exactly one question
        val (name, end) = readName(message, HEADER) ?: return DnsParse.Refuse(id, RCODE_FORMERR)
        if (end + 4 > message.size) return DnsParse.Refuse(id, RCODE_FORMERR)
        val question = DnsQuestion(name, u16(message, end), u16(message, end + 2))
        return DnsParse.Query(DnsQuery(id, flags, question, end + 4, message))
    }

    /**
     * Reads a (possibly compressed) name at [start]. Returns the name and the offset after it in
     * the message (after the first pointer, if any), or null if it is malformed: a label over 63
     * bytes, a name over 255, a pointer loop or a read past the end.
     */
    fun readName(message: ByteArray, start: Int): Pair<String, Int>? {
        val name = StringBuilder()
        var offset = start
        var end = -1
        var jumps = 0
        var length = 0
        while (true) {
            if (offset >= message.size) return null
            val len = message[offset].toInt() and 0xFF
            when {
                len == 0 -> {
                    if (end < 0) end = offset + 1
                    return name.toString() to end
                }

                len and 0xC0 == 0xC0 -> {
                    if (offset + 1 >= message.size || ++jumps > MAX_POINTERS) return null
                    if (end < 0) end = offset + 2
                    offset = ((len and 0x3F) shl 8) or (message[offset + 1].toInt() and 0xFF)
                }

                len and 0xC0 != 0 || len > MAX_LABEL -> return null

                // reserved label types

                else -> {
                    length += len + 1
                    if (length > MAX_NAME || offset + 1 + len > message.size) return null
                    if (name.isNotEmpty()) name.append('.')
                    for (i in offset + 1..offset + len) name.append(lower(message[i]))
                    offset += len + 1
                }
            }
        }
    }

    private fun lower(byte: Byte): Char {
        val c = (byte.toInt() and 0xFF).toChar()
        return if (c in 'A'..'Z') c + ('a' - 'A') else c
    }

    /** Name error: "this domain does not exist". No SOA, so resolvers do not cache it (RFC 2308). */
    fun nxdomain(query: DnsQuery): ByteArray = response(query, RCODE_NXDOMAIN, answers = 0)

    fun servfail(query: DnsQuery): ByteArray = response(query, RCODE_SERVFAIL, answers = 0)

    /** A header-only error response for a query whose question could not be used. */
    fun refuse(id: Int, rcode: Int): ByteArray = ByteArray(HEADER).also {
        put16(it, 0, id)
        put16(it, 2, FLAG_QR or FLAG_RA or rcode)
    }

    /**
     * Sinkhole: A queries get 0.0.0.0 and AAAA queries ::, with a 1 s TTL, so the connection fails
     * at once without a long-lived cache entry. Other types get an empty NOERROR answer.
     */
    fun sinkhole(query: DnsQuery): ByteArray {
        val address =
            when (query.question.type) {
                TYPE_A -> ByteArray(4)
                TYPE_AAAA -> ByteArray(16)
                else -> return response(query, rcode = 0, answers = 0)
            }
        val head = response(query, rcode = 0, answers = 1)
        val answer = ByteArray(12 + address.size)
        put16(answer, 0, 0xC000 or HEADER) // pointer to the question name
        put16(answer, 2, query.question.type)
        put16(answer, 4, CLASS_IN)
        answer[9] = SINKHOLE_TTL.toByte() // TTL (32-bit, big endian)
        put16(answer, 10, address.size)
        address.copyInto(answer, 12)
        return head + answer
    }

    private const val SINKHOLE_TTL = 1

    /** Header plus the original question; [answers] records must be appended by the caller. */
    private fun response(query: DnsQuery, rcode: Int, answers: Int): ByteArray {
        val out = ByteArray(query.questionEnd)
        query.raw.copyInto(out, 0, 0, query.questionEnd)
        put16(out, 2, FLAG_QR or (query.flags and RD_MASK) or FLAG_RA or rcode)
        put16(out, 4, 1)
        put16(out, 6, answers)
        put16(out, 8, 0)
        put16(out, 10, 0) // drop the client's EDNS OPT record: we answer without it
        return out
    }

    /** A minimal query, for tests and the resolver health check. */
    fun query(id: Int, name: String, type: Int = TYPE_A): ByteArray {
        val labels = name.trimEnd('.').split('.').filter { it.isNotEmpty() }
        val size = HEADER + labels.sumOf { it.length + 1 } + 1 + 4
        val out = ByteArray(size)
        put16(out, 0, id)
        put16(out, 2, RD_MASK)
        put16(out, 4, 1)
        var offset = HEADER
        for (label in labels) {
            out[offset++] = label.length.toByte()
            label.toByteArray(Charsets.US_ASCII).copyInto(out, offset)
            offset += label.length
        }
        out[offset++] = 0
        put16(out, offset, type)
        put16(out, offset + 2, CLASS_IN)
        return out
    }
}
