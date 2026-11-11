package com.itsash.netshield

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.BufferedReader
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.StringReader

class CoreTest {
    private fun name(n: String): ByteArray {
        val o = ByteArrayOutputStream()
        for (label in n.split('.')) {
            o.write(label.length)
            o.write(label.toByteArray())
        }
        o.write(0)
        return o.toByteArray()
    }

    private fun query(n: String, type: Int, id: Int = 0x1234): ByteArray {
        val head = byteArrayOf((id ushr 8).toByte(), id.toByte(), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0)
        return head + name(n) + byteArrayOf(0, type.toByte(), 0, 1)
    }

    private fun rr(nameBytes: ByteArray, type: Int, ttl: Int, data: ByteArray): ByteArray =
        nameBytes + byteArrayOf(
            0, type.toByte(), 0, 1,
            (ttl ushr 24).toByte(), (ttl ushr 16).toByte(), (ttl ushr 8).toByte(), ttl.toByte(),
            (data.size ushr 8).toByte(), data.size.toByte(),
        ) + data

    // ---- DNS ----

    @Test
    fun parsesQuery() {
        val q = DnsMessage.parseQuery(query("Ads.Example.COM", DnsMessage.TYPE_A))!!
        assertEquals("ads.example.com", q.name)
        assertEquals(DnsMessage.TYPE_A, q.type)
        assertEquals(0x1234, q.id)
    }

    @Test
    fun rejectsResponsesAndJunk() {
        val r = query("a.com", 1)
        r[2] = (r[2].toInt() or 0x80).toByte()
        assertNull(DnsMessage.parseQuery(r))
        assertNull(DnsMessage.parseQuery(ByteArray(5)))
        assertNull(DnsMessage.parseQuery(query("a.com", 1).copyOf(16)))
    }

    @Test
    fun blockedAnswerIsZeroAddress() {
        val qb = query("ads.example.com", DnsMessage.TYPE_A)
        val q = DnsMessage.parseQuery(qb)!!
        val r = DnsMessage.blockedResponse(qb, q)
        assertEquals(0x12, r[0].toInt())
        assertTrue(r[2].toInt() and 0x80 != 0) // QR
        assertEquals(1, DnsMessage.u16(r, 6)) // one answer
        val a = DnsMessage.parseAnswer(r)!!
        assertEquals(listOf("0.0.0.0"), a.ips)
        assertEquals(DnsMessage.BLOCKED_TTL, a.minTtl)
        assertTrue(a.nullAnswer)

        val q6b = query("ads.example.com", DnsMessage.TYPE_AAAA)
        val a6 = DnsMessage.parseAnswer(DnsMessage.blockedResponse(q6b, DnsMessage.parseQuery(q6b)!!))!!
        assertTrue(a6.nullAnswer)

        val httpsB = query("ads.example.com", 65)
        val rh = DnsMessage.blockedResponse(httpsB, DnsMessage.parseQuery(httpsB)!!)
        assertEquals(0, DnsMessage.u16(rh, 6)) // NODATA
        assertEquals(0, rh[3].toInt() and 0x0f)
    }

    @Test
    fun servfailKeepsQuestion() {
        val qb = query("x.org", 1)
        val r = DnsMessage.servfail(qb, DnsMessage.parseQuery(qb)!!)
        assertEquals(2, r[3].toInt() and 0x0f)
        assertEquals(qb.size, r.size)
    }

    @Test
    fun readsCnameChainAndTtl() {
        val qb = query("www.shop.com", 1)
        val head = qb.copyOf()
        head[2] = 0x81.toByte()
        head[3] = 0x80.toByte()
        head[7] = 2 // two answers
        val ptr = byteArrayOf(0xc0.toByte(), 12)
        val cnameData = name("tracker.adnet.net")
        val answer = head +
            rr(ptr, DnsMessage.TYPE_CNAME, 300, cnameData) +
            rr(name("tracker.adnet.net"), DnsMessage.TYPE_A, 60, byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), 34))
        val a = DnsMessage.parseAnswer(answer)!!
        assertEquals(listOf("tracker.adnet.net"), a.cnames)
        assertEquals(listOf("93.184.216.34"), a.ips)
        assertEquals(60, a.minTtl)
        assertFalse(a.nullAnswer)
    }

    @Test
    fun withIdChangesOnlyTheId() {
        val qb = query("a.com", 1, id = 1)
        val c = DnsMessage.withId(qb, 0xBEEF)
        assertEquals(0xBEEF, DnsMessage.u16(c, 0))
        assertEquals(1, DnsMessage.u16(qb, 0))
        assertTrue(qb.copyOfRange(2, qb.size).contentEquals(c.copyOfRange(2, c.size)))
    }

    // ---- Packets ----

    @Test
    fun udpRoundTripV4() {
        val src = byteArrayOf(10, 111, 222.toByte(), 2)
        val dst = byteArrayOf(10, 111, 222.toByte(), 1)
        val data = query("a.com", 1)
        val p = Packets.udp(src, dst, 53, 40000, data)
        assertTrue(Packets.verify(p))
        val ip = Packets.parse(p, p.size)!!
        assertFalse(ip.v6)
        assertEquals(Packets.UDP, ip.proto)
        assertEquals(53, Packets.u16(p, ip.off))
        assertEquals(40000, Packets.u16(p, ip.off + 2))
        assertTrue(p.copyOfRange(ip.off + 8, ip.end).contentEquals(data))
    }

    @Test
    fun udpRoundTripV6() {
        val src = ByteArray(16).also { it[0] = 0xfd.toByte(); it[15] = 2 }
        val dst = ByteArray(16).also { it[0] = 0xfd.toByte(); it[15] = 1 }
        val p = Packets.udp(src, dst, 53, 1234, ByteArray(33) { it.toByte() })
        assertTrue(Packets.verify(p))
        val ip = Packets.parse(p, p.size)!!
        assertTrue(ip.v6)
        assertEquals(40, ip.off)
    }

    @Test
    fun fragmentsAreIgnored() {
        val p = Packets.udp(byteArrayOf(1, 2, 3, 4), byteArrayOf(5, 6, 7, 8), 1, 53, ByteArray(10))
        p[6] = 0x20 // MF
        assertNull(Packets.parse(p, p.size))
    }

    private fun tcpSyn(): ByteArray {
        // A SYN from 10.0.0.5:50000 to 1.1.1.1:443, built by hand.
        val p = ByteArray(40)
        p[0] = 0x45
        p[3] = 40
        p[8] = 64
        p[9] = 6
        byteArrayOf(10, 0, 0, 5).copyInto(p, 12)
        byteArrayOf(1, 1, 1, 1).copyInto(p, 16)
        p[20] = (50000 ushr 8).toByte(); p[21] = 50000.toByte()
        p[22] = 1; p[23] = 0xbb.toByte()
        p[24] = 0; p[25] = 0; p[26] = 0x10; p[27] = 0 // seq 4096
        p[32] = 0x50
        p[33] = 0x02 // SYN
        return p
    }

    @Test
    fun resetAnswersSyn() {
        val syn = tcpSyn()
        val ip = Packets.parse(syn, syn.size)!!
        val rst = Packets.tcpReset(syn, ip)!!
        assertTrue(Packets.verify(rst))
        val r = Packets.parse(rst, rst.size)!!
        assertTrue(r.src.contentEquals(byteArrayOf(1, 1, 1, 1)))
        assertEquals(443, Packets.u16(rst, r.off))
        assertEquals(50000, Packets.u16(rst, r.off + 2))
        assertEquals(0x14, rst[r.off + 13].toInt()) // RST + ACK
        assertEquals(4097, Packets.u16(rst, r.off + 10)) // ack = seq + 1
    }

    @Test
    fun noResetForReset() {
        val p = tcpSyn()
        p[33] = 0x04
        assertNull(Packets.tcpReset(p, Packets.parse(p, p.size)!!))
    }

    // ---- Lists ----

    private fun rules(line: String): List<ParsedRule> {
        val out = ArrayList<ParsedRule>()
        RuleParser.parse(line) { out.add(it) }
        return out
    }

    @Test
    fun parsesListFormats() {
        assertEquals(listOf(ParsedRule(false, false, "ads.example.com")), rules("||ads.example.com^"))
        assertEquals(listOf(ParsedRule(false, false, "ads.example.com")), rules("||Ads.Example.com^\$important"))
        assertEquals(listOf(ParsedRule(true, false, "ok.example.com")), rules("@@||ok.example.com^"))
        assertEquals(listOf(ParsedRule(false, true, "track.me")), rules("0.0.0.0 track.me # comment"))
        assertEquals(listOf(ParsedRule(false, true, "a.me"), ParsedRule(false, true, "b.me")), rules("127.0.0.1 a.me b.me"))
        assertEquals(listOf(ParsedRule(false, true, "plain.example.org")), rules("plain.example.org"))
        assertEquals(listOf(ParsedRule(false, false, "ad-*.cdn.com")), rules("||ad-*.cdn.com^"))
        assertEquals(listOf(ParsedRule(false, false, "rgfftupf.*")), rules("||rgfftupf."))
        assertEquals(listOf(ParsedRule(false, false, "bbelements.com")), rules(".bbelements.com^"))
    }

    @Test
    fun skipsWhatDnsCannotUse() {
        for (l in listOf(
            "! comment", "# comment", "[Adblock Plus]", "", "/^ads[0-9]+\\./", "||ads.com^\$third-party",
            "||ads.com^\$badfilter", "|https://x.com/ad.js", "127.0.0.1 localhost", "0.0.0.0 0.0.0.0",
            "||1.2.3.4^", "example.com##.banner",
        )) {
            assertTrue("should skip: $l", rules(l).isEmpty())
        }
    }

    private fun build(text: String): Blocklist =
        BlocklistBuilder().apply { addAll(BufferedReader(StringReader(text))) }.build()

    @Test
    fun matchesSuffixExactWildcardAndExceptions() {
        val b = build(
            """
            ||doubleclick.net^
            0.0.0.0 exact.tracker.com
            ||ad-*.cdn.com^
            ||rgfftupf.
            ||ads.google.com^
            @@||ok.ads.google.com^
            """.trimIndent(),
        )
        assertEquals(Blocklist.BLOCK, b.match("doubleclick.net"))
        assertEquals(Blocklist.BLOCK, b.match("stats.g.doubleclick.net"))
        assertEquals(Blocklist.NONE, b.match("notdoubleclick.net"))
        assertEquals(Blocklist.BLOCK, b.match("exact.tracker.com"))
        assertEquals(Blocklist.NONE, b.match("sub.exact.tracker.com"))
        assertEquals(Blocklist.BLOCK, b.match("ad-77.cdn.com"))
        assertEquals(Blocklist.BLOCK, b.match("x.ad-1.cdn.com"))
        assertEquals(Blocklist.NONE, b.match("img.cdn.com"))
        assertEquals(Blocklist.BLOCK, b.match("rgfftupf.example.org"))
        assertEquals(Blocklist.ALLOW, b.match("ok.ads.google.com"))
        assertEquals(Blocklist.BLOCK, b.match("ads.google.com."))
        assertEquals(Blocklist.NONE, b.match("google.com"))
    }

    @Test
    fun compiledListSurvivesDisk() {
        val b = build("||doubleclick.net^\n0.0.0.0 x.y.com\n||ad-*.cdn.com^\n@@||ok.doubleclick.net^")
        val f = File.createTempFile("netshield", ".bin")
        try {
            b.write(f)
            val r = Blocklist.read(f)!!
            assertEquals(b.size, r.size)
            assertEquals(Blocklist.BLOCK, r.match("a.doubleclick.net"))
            assertEquals(Blocklist.ALLOW, r.match("ok.doubleclick.net"))
            assertEquals(Blocklist.BLOCK, r.match("x.y.com"))
            assertEquals(Blocklist.BLOCK, r.match("ad-2.cdn.com"))
        } finally {
            f.delete()
        }
        val junk = File.createTempFile("netshield", ".bin")
        junk.writeText("not a list")
        assertNull(Blocklist.read(junk))
        junk.delete()
    }

    // ---- Rules and filter ----

    @Test
    fun normalizesUserInput() {
        assertEquals("ads.example.com", UserRules.normalize("https://Ads.Example.com/path?x=1"))
        assertEquals("ads.example.com", UserRules.normalize("*.ads.example.com"))
        assertEquals("ads.example.com", UserRules.normalize("||ads.example.com^"))
        assertEquals("ads.example.com", UserRules.normalize("ads.example.com:443"))
        assertNull(UserRules.normalize("localhost"))
        assertNull(UserRules.normalize("bad domain.com"))
        assertNull(UserRules.normalize(""))
    }

    @Test
    fun ruleOrderAppThenGlobalThenLists() {
        val f = DnsFilter(
            build("||ads.net^\n||tracker.io^"),
            UserRules(
                allow = setOf("good.ads.net"),
                block = setOf("social.com"),
                appAllow = mapOf("com.bank" to setOf("tracker.io")),
                appBlock = mapOf("com.game" to setOf("cdn.game.com"), "com.bank" to setOf("social.com")),
            ),
        )
        assertEquals(Verdict.BLOCKED_LIST, f.decide("x.ads.net", null))
        assertEquals(Verdict.ALLOWED_RULE, f.decide("good.ads.net", null))
        assertEquals(Verdict.BLOCKED_RULE, f.decide("api.social.com", null))
        assertEquals(Verdict.ALLOWED, f.decide("example.com", null))
        assertEquals(Verdict.ALLOWED_RULE, f.decide("tracker.io", "com.bank"))
        assertEquals(Verdict.BLOCKED_LIST, f.decide("tracker.io", "com.other"))
        assertEquals(Verdict.BLOCKED_APP_RULE, f.decide("img.cdn.game.com", "com.game"))
        assertEquals(Verdict.ALLOWED, f.decide("img.cdn.game.com", "com.other"))
        assertEquals(Verdict.BLOCKED_APP_RULE, f.decide("social.com", "com.bank"))
    }

    // ---- Log and cache ----

    @Test
    fun logKeepsNewestAndCounts() {
        val log = QueryLog(capacity = 3)
        for (i in 1..5) log.add(i.toLong(), "d$i.com", 1, 10000, "com.app", if (i % 2 == 0) Verdict.BLOCKED_LIST else Verdict.ALLOWED, 1, null)
        val all = log.since(0, 10)
        assertEquals(listOf("d5.com", "d4.com", "d3.com"), all.map { it.domain })
        assertEquals(listOf("d5.com"), log.since(all[1].id, 10).map { it.domain })
        assertEquals(5L, log.total)
        assertEquals(2L, log.blocked)
        assertTrue(log.appCounts()["com.app"]!!.contentEquals(longArrayOf(5, 2)))
        assertEquals("uid:1000", QueryLog.appKey(1000, null))
        assertEquals("unknown", QueryLog.appKey(-1, null))
    }

    @Test
    fun cacheHonoursTtl() {
        val c = DnsCache(max = 2)
        c.put("a.com", 1, byteArrayOf(1), 60, now = 0)
        assertNotNull(c.get("a.com", 1, now = 59_000))
        assertNull(c.get("a.com", 1, now = 60_000))
        assertNull(c.get("a.com", 28, now = 0))
        c.put("b.com", 1, byteArrayOf(2), 0, now = 0) // TTL 0: not cached
        assertNull(c.get("b.com", 1, now = 0))
        c.put("x.com", 1, byteArrayOf(3), 1, now = 0) // clamped up to 10 s
        assertNotNull(c.get("x.com", 1, now = 9_000))
    }
}
