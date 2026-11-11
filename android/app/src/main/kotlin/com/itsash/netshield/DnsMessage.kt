package com.itsash.netshield

import java.net.InetAddress
import java.util.Locale

/**
 * DNS wire format (RFC 1035), only what NetShield needs: read a query, build a
 * blocked or failed answer, and read the answers of an upstream response
 * (TTL, CNAME chain, addresses). Pure Kotlin, unit tested.
 */
object DnsMessage {
    const val TYPE_A = 1
    const val TYPE_CNAME = 5
    const val TYPE_AAAA = 28

    /** TTL of a blocked answer: short, so an unblock takes effect quickly. */
    const val BLOCKED_TTL = 10

    class Question(val id: Int, val name: String, val type: Int, val end: Int)

    class Answer(
        val rcode: Int,
        val minTtl: Int,
        val cnames: List<String>,
        val ips: List<String>,
    ) {
        /** The upstream itself blocked the name (answers 0.0.0.0 / ::). */
        val nullAnswer: Boolean get() = ips.isNotEmpty() && ips.all { it == "0.0.0.0" || it == "::" || it == "0:0:0:0:0:0:0:0" }
    }

    fun u16(b: ByteArray, i: Int): Int = ((b[i].toInt() and 0xff) shl 8) or (b[i + 1].toInt() and 0xff)

    private fun u32(b: ByteArray, i: Int): Long =
        (u16(b, i).toLong() shl 16) or u16(b, i + 2).toLong()

    private fun put16(b: ByteArray, i: Int, v: Int) {
        b[i] = (v ushr 8).toByte()
        b[i + 1] = v.toByte()
    }

    /** The first question of a query, or null when [b] is not a usable query. */
    fun parseQuery(b: ByteArray): Question? {
        if (b.size < 12) return null
        if (b[2].toInt() and 0x80 != 0) return null // QR set: a response
        if (u16(b, 4) < 1) return null
        val (name, next) = readName(b, 12) ?: return null
        if (next + 4 > b.size) return null
        return Question(u16(b, 0), name, u16(b, next), next + 4)
    }

    /**
     * Reads a possibly compressed name at [start]. Returns the lowercase name and
     * the offset right after the name at its original position.
     */
    fun readName(b: ByteArray, start: Int): Pair<String, Int>? {
        val sb = StringBuilder()
        var i = start
        var end = -1
        var jumps = 0
        while (true) {
            if (i >= b.size) return null
            val len = b[i].toInt() and 0xff
            when {
                len == 0 -> {
                    if (end < 0) end = i + 1
                    return sb.toString().lowercase(Locale.ROOT) to end
                }
                len and 0xc0 == 0xc0 -> {
                    if (i + 1 >= b.size || ++jumps > 32) return null
                    if (end < 0) end = i + 2
                    i = ((len and 0x3f) shl 8) or (b[i + 1].toInt() and 0xff)
                }
                len and 0xc0 != 0 -> return null
                else -> {
                    if (i + 1 + len > b.size) return null
                    if (sb.isNotEmpty()) sb.append('.')
                    for (k in 1..len) sb.append((b[i + k].toInt() and 0xff).toChar())
                    if (sb.length > 255) return null
                    i += 1 + len
                }
            }
        }
    }

    /** Header plus the first question of [query], turned into a response with [rcode]. */
    private fun responseHead(query: ByteArray, q: Question, rcode: Int, answers: Int): ByteArray {
        val head = query.copyOf(q.end)
        // QR=1, keep opcode and RD; AA=0, TC=0.
        head[2] = (0x80 or (query[2].toInt() and 0x79)).toByte()
        head[3] = (0x80 or (rcode and 0x0f)).toByte() // RA=1
        put16(head, 4, 1)
        put16(head, 6, answers)
        put16(head, 8, 0)
        put16(head, 10, 0)
        return head
    }

    /**
     * Answer for a blocked name: 0.0.0.0 for A, :: for AAAA (apps fail fast and
     * do not retry), and an empty NOERROR answer for every other type.
     */
    fun blockedResponse(query: ByteArray, q: Question): ByteArray {
        val rdata = when (q.type) {
            TYPE_A -> ByteArray(4)
            TYPE_AAAA -> ByteArray(16)
            else -> return responseHead(query, q, 0, 0)
        }
        val head = responseHead(query, q, 0, 1)
        val rr = ByteArray(12 + rdata.size)
        rr[0] = 0xc0.toByte() // name: pointer to the question name at offset 12
        rr[1] = 0x0c
        put16(rr, 2, q.type)
        put16(rr, 4, 1) // class IN
        put16(rr, 6, 0)
        put16(rr, 8, BLOCKED_TTL)
        put16(rr, 10, rdata.size)
        return head + rr
    }

    /** SERVFAIL for [query]: the upstream could not be reached. */
    fun servfail(query: ByteArray, q: Question): ByteArray = responseHead(query, q, 2, 0)

    /** A copy of [msg] with the transaction id set to [id]. */
    fun withId(msg: ByteArray, id: Int): ByteArray {
        val c = msg.copyOf()
        put16(c, 0, id)
        return c
    }

    /** Sets the transaction id in place (DoH asks for id 0 for better caching). */
    fun setId(msg: ByteArray, id: Int) = put16(msg, 0, id)

    /** Reads the answer section of a response. Null when it cannot be parsed. */
    fun parseAnswer(b: ByteArray): Answer? {
        if (b.size < 12) return null
        val rcode = b[3].toInt() and 0x0f
        val qd = u16(b, 4)
        val an = u16(b, 6)
        val ns = u16(b, 8)
        var i = 12
        repeat(qd) {
            val (_, next) = readName(b, i) ?: return null
            i = next + 4
        }
        val cnames = ArrayList<String>()
        val ips = ArrayList<String>()
        var minTtl = Int.MAX_VALUE
        repeat(an + ns) { n ->
            val (_, next) = readName(b, i) ?: return null
            if (next + 10 > b.size) return null
            val type = u16(b, next)
            val ttl = u32(b, next + 4).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
            val len = u16(b, next + 8)
            val data = next + 10
            if (data + len > b.size) return null
            // Authority records (SOA) give the TTL of a negative answer.
            minTtl = minOf(minTtl, ttl)
            if (n < an) {
                when (type) {
                    TYPE_CNAME -> readName(b, data)?.let { cnames.add(it.first) }
                    TYPE_A -> if (len == 4) ips.add(InetAddress.getByAddress(b.copyOfRange(data, data + 4)).hostAddress!!)
                    TYPE_AAAA -> if (len == 16) ips.add(InetAddress.getByAddress(b.copyOfRange(data, data + 16)).hostAddress!!)
                }
            }
            i = data + len
        }
        return Answer(rcode, if (minTtl == Int.MAX_VALUE) 0 else minTtl, cnames, ips)
    }
}
