package com.itsash.netshield

import java.util.Locale

/** Why a query was answered the way it was. Shared with the Dart side by number. */
object Verdict {
    const val ALLOWED = 0
    const val BLOCKED_LIST = 1
    const val BLOCKED_RULE = 2
    const val BLOCKED_APP_RULE = 3
    const val BLOCKED_CNAME = 4
    const val BLOCKED_UPSTREAM = 5
    const val ALLOWED_RULE = 6
    const val ERROR = 7

    fun blocked(v: Int) = v in BLOCKED_LIST..BLOCKED_UPSTREAM
}

/**
 * The user's own rules. Every domain also covers its subdomains. App rules
 * are keyed by package name and only apply to queries from that app.
 */
class UserRules(
    val allow: Set<String> = emptySet(),
    val block: Set<String> = emptySet(),
    val appAllow: Map<String, Set<String>> = emptyMap(),
    val appBlock: Map<String, Set<String>> = emptyMap(),
) {
    companion object {
        /** Lowercase, no scheme, path, port, "*." or trailing dot. Null when it is not a domain. */
        fun normalize(input: String): String? {
            var d = input.trim().lowercase(Locale.ROOT)
            d = d.substringAfter("://").substringBefore('/').substringBefore(':')
            d = d.removePrefix("*.").removePrefix("||").trimEnd('^', '.')
            if (d.isEmpty() || d.length > 253 || !d.contains('.')) return null
            if (d.any { !(it in 'a'..'z' || it in '0'..'9' || it == '.' || it == '-' || it == '_') }) return null
            if (d.startsWith('.') || d.contains("..")) return null
            return d
        }

        /** True when [d] or one of its parent domains is in [set]. */
        fun suffixIn(set: Set<String>?, d: String): Boolean {
            if (set.isNullOrEmpty()) return false
            var s = d
            while (true) {
                if (s in set) return true
                val dot = s.indexOf('.')
                if (dot < 0) return false
                s = s.substring(dot + 1)
            }
        }
    }
}

/**
 * Decides one name. Order: the app's allow, the app's block, your allow,
 * your block, list exceptions, lists. So a rule you made always wins over the
 * lists, and an app rule wins over a global one.
 */
class DnsFilter(
    @Volatile var lists: Blocklist = Blocklist.EMPTY,
    @Volatile var rules: UserRules = UserRules(),
) {
    fun decide(domain: String, pkg: String?): Int {
        val d = domain.trimEnd('.').lowercase(Locale.ROOT)
        val r = rules
        if (pkg != null) {
            if (UserRules.suffixIn(r.appAllow[pkg], d)) return Verdict.ALLOWED_RULE
            if (UserRules.suffixIn(r.appBlock[pkg], d)) return Verdict.BLOCKED_APP_RULE
        }
        if (UserRules.suffixIn(r.allow, d)) return Verdict.ALLOWED_RULE
        if (UserRules.suffixIn(r.block, d)) return Verdict.BLOCKED_RULE
        return if (lists.match(d) == Blocklist.BLOCK) Verdict.BLOCKED_LIST else Verdict.ALLOWED
    }
}

class LogEntry(
    val id: Long,
    val time: Long,
    val domain: String,
    val type: Int,
    val uid: Int,
    val pkg: String?,
    val verdict: Int,
    val ms: Int,
    val detail: String?,
)

/** Recent queries (a ring of [capacity]) plus per-app counters since the service started. */
class QueryLog(private val capacity: Int = 5000) {
    private val ring = ArrayDeque<LogEntry>()
    private var nextId = 1L
    private val apps = HashMap<String, LongArray>()

    var total = 0L
        private set
    var blocked = 0L
        private set

    @Synchronized
    fun add(time: Long, domain: String, type: Int, uid: Int, pkg: String?, verdict: Int, ms: Int, detail: String?): LogEntry {
        val e = LogEntry(nextId++, time, domain, type, uid, pkg, verdict, ms, detail)
        ring.addLast(e)
        if (ring.size > capacity) ring.removeFirst()
        total++
        val b = Verdict.blocked(verdict)
        if (b) blocked++
        val c = apps.getOrPut(appKey(uid, pkg)) { LongArray(2) }
        c[0]++
        if (b) c[1]++
        return e
    }

    /** Entries newer than [afterId], newest first, at most [limit]. */
    @Synchronized
    fun since(afterId: Long, limit: Int): List<LogEntry> {
        val out = ArrayList<LogEntry>()
        val it = ring.listIterator(ring.size)
        while (it.hasPrevious() && out.size < limit) {
            val e = it.previous()
            if (e.id <= afterId) break
            out.add(e)
        }
        return out
    }

    /** key → [queries, blocked]. The key is the package, "uid:N", or "unknown". */
    @Synchronized
    fun appCounts(): Map<String, LongArray> = apps.mapValues { it.value.copyOf() }

    @Synchronized
    fun clear() {
        ring.clear()
        apps.clear()
        total = 0
        blocked = 0
    }

    companion object {
        fun appKey(uid: Int, pkg: String?) = pkg ?: if (uid >= 0) "uid:$uid" else "unknown"
    }
}

/** Small LRU cache of upstream answers, honouring their TTL. */
class DnsCache(private val max: Int = 4096) {
    private class Item(val data: ByteArray, val expires: Long)

    private val map = object : LinkedHashMap<String, Item>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Item>?) = size > max
    }

    @Synchronized
    fun get(name: String, type: Int, now: Long): ByteArray? {
        val key = "$type/$name"
        val it = map[key] ?: return null
        if (it.expires <= now) {
            map.remove(key)
            return null
        }
        return it.data
    }

    @Synchronized
    fun put(name: String, type: Int, data: ByteArray, ttlSeconds: Int, now: Long) {
        if (ttlSeconds <= 0) return
        map["$type/$name"] = Item(data, now + ttlSeconds.coerceIn(10, 3600) * 1000L)
    }

    @Synchronized
    fun clear() = map.clear()
}
