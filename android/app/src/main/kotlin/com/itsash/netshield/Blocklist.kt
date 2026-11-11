package com.itsash.netshield

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.BufferedReader
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.util.Arrays
import java.util.Locale

/** 64-bit FNV-1a of a domain (or of its suffix starting at [from]). */
object DomainHash {
    fun of(s: String, from: Int = 0): Long {
        var h = -0x340d631b7bdddcdbL
        for (i in from until s.length) {
            h = h xor (s[i].code.toLong() and 0xff)
            h *= 0x100000001b3L
        }
        return h
    }
}

/** One rule from a list: block or allow [pattern], exactly or with all subdomains. */
data class ParsedRule(val allow: Boolean, val exact: Boolean, val pattern: String) {
    val wildcard: Boolean get() = '*' in pattern
}

/**
 * Reads hosts files ("0.0.0.0 ads.example.com"), plain domain lists and
 * adblock DNS syntax ("||ads.example.com^", "@@||ok.example.com^", wildcards,
 * "$important"). Regex rules and rules with other modifiers are skipped, as
 * AdGuard Home does.
 */
object RuleParser {
    private val ws = Regex("\\s+")
    private val hostsJunk = setOf(
        "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost",
        "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters",
        "ip6-allhosts", "0.0.0.0",
    )

    fun parse(raw: String, out: (ParsedRule) -> Unit) {
        var s = raw.trim()
        if (s.isEmpty() || s[0] == '!' || s[0] == '#' || s[0] == '[') return
        val comment = s.indexOf(" #").let { if (it < 0) s.indexOf("\t#") else it }
        if (comment >= 0) s = s.substring(0, comment).trim()
        var allow = false
        if (s.startsWith("@@")) {
            allow = true
            s = s.substring(2)
        }
        if (s.isEmpty() || s[0] == '/') return // regex rule
        val dollar = s.indexOf('$')
        if (dollar >= 0) {
            val mods = s.substring(dollar + 1).split(',').map { it.trim() }
            if (mods.any { it != "important" }) return
            s = s.substring(0, dollar)
        }
        when {
            s.startsWith("||") -> emit(s.substring(2), allow, exact = false, out)
            s.startsWith("|") -> return // URL rule
            s.startsWith(".") -> emit(s.substring(1), allow, exact = false, out)
            else -> {
                val parts = s.split(ws)
                if (parts.size >= 2 && isIp(parts[0])) {
                    for (k in 1 until parts.size) emit(parts[k], allow, exact = true, out)
                } else if (parts.size == 1) {
                    // Adblock style lists mean "and subdomains"; plain domain lists list
                    // the subdomains they want, so exact is right for them.
                    val adblock = s.endsWith("^")
                    emit(s, allow, exact = !adblock, out)
                }
            }
        }
    }

    private fun emit(body0: String, allow: Boolean, exact: Boolean, out: (ParsedRule) -> Unit) {
        var body = body0.trimEnd('^', '|').lowercase(Locale.ROOT)
        if (body.endsWith(".")) body = "$body*" // "||prefix." = any name starting with that label
        if (body.isEmpty() || body.length > 253 || body in hostsJunk) return
        if (body[0] == '.' || body.contains("..")) return
        for (c in body) {
            if (!(c in 'a'..'z' || c in '0'..'9' || c == '.' || c == '-' || c == '_' || c == '*')) return
        }
        if (isIp(body)) return
        out(ParsedRule(allow, exact, body))
    }

    fun isIp(s: String): Boolean =
        (s.isNotEmpty() && s.all { it.isDigit() || it == '.' } && s.count { it == '.' } == 3) ||
            (s.contains(':') && s.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' })
}

/** Growable LongArray that sorts and drops duplicates at the end. */
class LongSetBuilder {
    private var a = LongArray(4096)
    private var n = 0

    fun add(v: Long) {
        if (n == a.size) a = a.copyOf(a.size * 2)
        a[n++] = v
    }

    fun build(): LongArray {
        val s = a.copyOf(n)
        s.sort()
        var w = 0
        for (i in s.indices) if (i == 0 || s[i] != s[i - 1]) s[w++] = s[i]
        return s.copyOf(w)
    }
}

/**
 * The compiled blocklists. Domains are kept as sorted 64-bit hashes, so two
 * million domains take about 16 MB and a lookup is a few binary searches.
 * Wildcard rules are joined into one regex.
 */
class Blocklist(
    private val block: LongArray,
    private val exact: LongArray,
    private val allow: LongArray,
    private val blockWild: List<String>,
    private val allowWild: List<String>,
) {
    val size: Int get() = block.size + exact.size + blockWild.size

    private val blockRegex = regexOf(blockWild)
    private val allowRegex = regexOf(allowWild)

    /** [NONE], [BLOCK] or [ALLOW] (a list exception) for a lowercase [domain]. */
    fun match(domain: String): Int {
        val d = domain.trimEnd('.')
        if (d.isEmpty()) return NONE
        if (anySuffix(allow, d) || allowRegex?.containsMatchIn(d) == true) return ALLOW
        if (Arrays.binarySearch(exact, DomainHash.of(d)) >= 0) return BLOCK
        if (anySuffix(block, d) || blockRegex?.containsMatchIn(d) == true) return BLOCK
        return NONE
    }

    private fun anySuffix(set: LongArray, d: String): Boolean {
        if (set.isEmpty()) return false
        var i = 0
        while (true) {
            if (Arrays.binarySearch(set, DomainHash.of(d, i)) >= 0) return true
            val dot = d.indexOf('.', i)
            if (dot < 0) return false
            i = dot + 1
        }
    }

    fun write(file: File) {
        val tmp = File(file.path + ".tmp")
        DataOutputStream(BufferedOutputStream(tmp.outputStream(), 1 shl 16)).use { o ->
            o.writeInt(MAGIC)
            for (arr in listOf(block, exact, allow)) {
                o.writeInt(arr.size)
                val bb = ByteBuffer.allocate(arr.size * 8)
                bb.asLongBuffer().put(arr)
                o.write(bb.array())
            }
            for (w in listOf(blockWild, allowWild)) {
                o.writeInt(w.size)
                for (p in w) o.writeUTF(p)
            }
        }
        if (!tmp.renameTo(file)) {
            file.delete()
            tmp.renameTo(file)
        }
    }

    companion object {
        const val NONE = 0
        const val BLOCK = 1
        const val ALLOW = 2
        private const val MAGIC = 0x4e534231 // "NSB1"

        val EMPTY = Blocklist(LongArray(0), LongArray(0), LongArray(0), emptyList(), emptyList())

        /** Glob with suffix meaning: "ads*.example.com" also matches "x.ads1.example.com". */
        fun globToRegex(glob: String): String =
            "(?:^|\\.)" + glob.split('*').joinToString(".*") { if (it.isEmpty()) "" else Regex.escape(it) } + "$"

        private fun regexOf(globs: List<String>): Regex? =
            if (globs.isEmpty()) null else Regex(globs.joinToString("|") { "(?:${globToRegex(it)})" })

        fun read(file: File): Blocklist? = try {
            DataInputStream(BufferedInputStream(file.inputStream(), 1 shl 16)).use { i ->
                if (i.readInt() != MAGIC) return null
                val arrays = (0 until 3).map {
                    val n = i.readInt()
                    val bytes = ByteArray(n * 8)
                    i.readFully(bytes)
                    val arr = LongArray(n)
                    ByteBuffer.wrap(bytes).asLongBuffer().get(arr)
                    arr
                }
                val wild = (0 until 2).map { List(i.readInt()) { i.readUTF() } }
                Blocklist(arrays[0], arrays[1], arrays[2], wild[0], wild[1])
            }
        } catch (_: Exception) {
            null
        }
    }
}

/** Collects rules from any number of lists into one [Blocklist]. */
class BlocklistBuilder {
    private val block = LongSetBuilder()
    private val exact = LongSetBuilder()
    private val allow = LongSetBuilder()
    private val blockWild = LinkedHashSet<String>()
    private val allowWild = LinkedHashSet<String>()

    fun add(r: ParsedRule) {
        when {
            r.wildcard -> (if (r.allow) allowWild else blockWild).add(r.pattern)
            r.allow -> allow.add(DomainHash.of(r.pattern))
            r.exact -> exact.add(DomainHash.of(r.pattern))
            else -> block.add(DomainHash.of(r.pattern))
        }
    }

    /** Adds every rule of a list; returns how many block rules it had. */
    fun addAll(reader: BufferedReader): Int {
        var n = 0
        reader.forEachLine { line ->
            RuleParser.parse(line) { r ->
                add(r)
                if (!r.allow) n++
            }
        }
        return n
    }

    fun build() = Blocklist(block.build(), exact.build(), allow.build(), blockWild.toList(), allowWild.toList())
}
