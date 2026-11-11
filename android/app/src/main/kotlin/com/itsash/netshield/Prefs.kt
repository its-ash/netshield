package com.itsash.netshield

import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.os.Build
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

/** Everything NetShield saves. The service and the UI share it (one process). */
class ShieldPrefs(ctx: Context) {
    val p: SharedPreferences = ctx.applicationContext.getSharedPreferences("netshield", Context.MODE_PRIVATE)

    /** The user wants protection on (restored after reboot and app updates). */
    var enabled: Boolean
        get() = p.getBoolean("enabled", false)
        set(v) = p.edit().putBoolean("enabled", v).apply()

    var upstream: String
        get() = p.getString("upstream", null) ?: UpstreamProvider.DEFAULT.key
        set(v) = p.edit().putString("upstream", v).apply()

    /** Also catch DNS sent straight to well-known public resolvers. */
    var interceptDns: Boolean
        get() = p.getBoolean("interceptDns", true)
        set(v) = p.edit().putBoolean("interceptDns", v).apply()

    var listsUpdatedAt: Long
        get() = p.getLong("lists.updatedAt", 0)
        set(v) = p.edit().putLong("lists.updatedAt", v).apply()

    var domainCount: Int
        get() = p.getInt("lists.domains", 0)
        set(v) = p.edit().putInt("lists.domains", v).apply()

    private fun set(key: String): Set<String> = p.getStringSet(key, null)?.toSet() ?: emptySet()

    private fun putSet(key: String, v: Set<String>) {
        if (v.isEmpty()) p.edit().remove(key).apply() else p.edit().putStringSet(key, HashSet(v)).apply()
    }

    /** Enabled list ids. The first read picks the recommended lists plus this phone's brand list. */
    fun enabledLists(): Set<String> {
        if (!p.contains("lists")) {
            putSet("lists", ListCatalog.all.filter { ListCatalog.defaultOn(it, Build.MANUFACTURER) }.map { it.id }.toSet())
        }
        return set("lists")
    }

    fun setListEnabled(id: String, on: Boolean) {
        val s = enabledLists().toMutableSet()
        if (on) s.add(id) else s.remove(id)
        putSet("lists", s)
    }

    fun listCount(id: String) = p.getInt("lists.count.$id", 0)
    fun setListCount(id: String, n: Int) = p.edit().putInt("lists.count.$id", n).apply()

    /** Apps that skip NetShield completely (for apps that break). */
    var bypass: Set<String>
        get() = set("bypass")
        set(v) = putSet("bypass", v)

    fun rules(): UserRules {
        val appAllow = HashMap<String, Set<String>>()
        val appBlock = HashMap<String, Set<String>>()
        for (k in p.all.keys) {
            when {
                k.startsWith("app.allow.") -> appAllow[k.removePrefix("app.allow.")] = set(k)
                k.startsWith("app.block.") -> appBlock[k.removePrefix("app.block.")] = set(k)
            }
        }
        return UserRules(set("rules.allow"), set("rules.block"), appAllow, appBlock)
    }

    private fun ruleKey(allow: Boolean, pkg: String?) =
        if (pkg == null) (if (allow) "rules.allow" else "rules.block") else (if (allow) "app.allow.$pkg" else "app.block.$pkg")

    /** Adds a rule and removes the opposite one for the same domain and scope. */
    fun addRule(domain: String, allow: Boolean, pkg: String?) {
        putSet(ruleKey(allow, pkg), set(ruleKey(allow, pkg)) + domain)
        putSet(ruleKey(!allow, pkg), set(ruleKey(!allow, pkg)) - domain)
    }

    fun removeRule(domain: String, allow: Boolean, pkg: String?) {
        putSet(ruleKey(allow, pkg), set(ruleKey(allow, pkg)) - domain)
    }
}

/** Queries and blocks today, kept across restarts of the service. */
object TodayStats {
    private var day = ""
    var total = 0L
        private set
    var blocked = 0L
        private set
    private var loaded = false

    private fun key() = SimpleDateFormat("yyyyMMdd", Locale.US).format(Date())

    @Synchronized
    private fun roll(prefs: ShieldPrefs) {
        val k = key()
        if (!loaded) {
            loaded = true
            day = prefs.p.getString("today.day", "") ?: ""
            total = prefs.p.getLong("today.total", 0)
            blocked = prefs.p.getLong("today.blocked", 0)
        }
        if (k != day) {
            day = k
            total = 0
            blocked = 0
        }
    }

    @Synchronized
    fun count(prefs: ShieldPrefs, wasBlocked: Boolean) {
        roll(prefs)
        total++
        if (wasBlocked) blocked++
    }

    @Synchronized
    fun read(prefs: ShieldPrefs): Pair<Long, Long> {
        roll(prefs)
        return total to blocked
    }

    @Synchronized
    fun save(prefs: ShieldPrefs) {
        roll(prefs)
        prefs.p.edit().putString("today.day", day).putLong("today.total", total).putLong("today.blocked", blocked).apply()
    }
}

class ListSource(
    val id: String,
    val name: String,
    val description: String,
    val group: String,
    val url: String,
    val recommended: Boolean,
    val brands: List<String> = emptyList(),
)

/** The lists NetShield offers. On by default: the strongest ad and tracker lists. */
object ListCatalog {
    private const val H = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/"
    private const val ADS = "Ads and trackers"
    private const val NATIVE = "Phone and app telemetry"

    val all = listOf(
        ListSource("hagezi_proplus", "HaGeZi Multi Pro++",
            "Ads, trackers, telemetry, scams and malware. The strongest everyday list; a rare site may break.",
            ADS, H + "pro.plus.txt", true),
        ListSource("oisd_big", "OISD Big",
            "Large list of ad, tracker and malware domains with very few false blocks.",
            ADS, "https://big.oisd.nl", true),
        ListSource("adguard_dns", "AdGuard DNS filter",
            "AdGuard's own list for DNS blocking. Strong on mobile ad networks.",
            ADS, "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", true),
        ListSource("stevenblack", "StevenBlack Unified",
            "Classic hosts list of ads and malware. Mostly covered by the lists above.",
            ADS, "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", false),
        ListSource("hagezi_doh", "Encrypted DNS bypass",
            "Blocks DNS-over-HTTPS servers, so browsers and apps cannot skip NetShield with their own DNS.",
            "Bypass protection", H + "doh.txt", true),
        ListSource("hagezi_tif", "Threat Intelligence Feeds",
            "About 1.5 million malware, phishing and scam domains. Uses about 12 MB more memory.",
            "Security", H + "tif.txt", false),
        ListSource("native_xiaomi", "Xiaomi, Redmi, POCO", "Built-in Xiaomi ads and tracking (MIUI / HyperOS).",
            NATIVE, H + "native.xiaomi.txt", false, listOf("xiaomi", "redmi", "poco")),
        ListSource("native_samsung", "Samsung", "Samsung telemetry and ads.",
            NATIVE, H + "native.samsung.txt", false, listOf("samsung")),
        ListSource("native_oppo", "OPPO, Realme, OnePlus", "ColorOS / realme UI ads and tracking.",
            NATIVE, H + "native.oppo-realme.txt", false, listOf("oppo", "realme", "oneplus")),
        ListSource("native_vivo", "vivo, iQOO", "Funtouch / OriginOS ads and tracking.",
            NATIVE, H + "native.vivo.txt", false, listOf("vivo", "iqoo")),
        ListSource("native_huawei", "Huawei, Honor", "Huawei and Honor telemetry.",
            NATIVE, H + "native.huawei.txt", false, listOf("huawei", "honor")),
        ListSource("native_tiktok", "TikTok", "TikTok tracking. Turning it on may break TikTok.",
            NATIVE, H + "native.tiktok.txt", false),
    )

    fun byId(id: String) = all.firstOrNull { it.id == id }

    fun defaultOn(s: ListSource, manufacturer: String): Boolean =
        s.recommended || s.brands.any { manufacturer.lowercase(Locale.ROOT).contains(it) }
}

/** Downloads the enabled lists and compiles them into one file the service loads. */
class ListManager(ctx: Context, private val prefs: ShieldPrefs) {
    private val dir = File(ctx.filesDir, "lists")
    private val compiled = File(ctx.filesDir, "compiled.bin")

    /** What an update is doing now, or null when idle. */
    @Volatile
    var progress: String? = null
        private set

    val ready: Boolean get() = compiled.exists()

    val stale: Boolean get() = System.currentTimeMillis() - prefs.listsUpdatedAt > STALE_MS

    fun load(): Blocklist = Blocklist.read(compiled) ?: Blocklist.EMPTY

    class Result(val domains: Int, val failed: List<String>)

    /**
     * Downloads missing lists (all enabled ones when [force] or stale) and
     * rebuilds. Blocking: call from a background thread. A list that fails to
     * download keeps its last good copy.
     */
    @Synchronized
    fun update(force: Boolean): Result {
        dir.mkdirs()
        val enabled = ListCatalog.all.filter { it.id in prefs.enabledLists() }
        val failed = ArrayList<String>()
        val refresh = force || stale
        try {
            for ((n, s) in enabled.withIndex()) {
                val f = File(dir, "${s.id}.txt")
                if (!refresh && f.exists()) continue
                progress = "Downloading ${s.name} (${n + 1} of ${enabled.size})"
                try {
                    download(s.url, f)
                } catch (e: IOException) {
                    failed.add(s.name)
                }
            }
            progress = "Building the blocklist"
            val b = BlocklistBuilder()
            for (s in enabled) {
                val f = File(dir, "${s.id}.txt")
                if (!f.exists()) continue
                prefs.setListCount(s.id, f.bufferedReader().use { b.addAll(it) })
            }
            val list = b.build()
            list.write(compiled)
            prefs.domainCount = list.size
            if (failed.size < enabled.size || enabled.isEmpty()) prefs.listsUpdatedAt = System.currentTimeMillis()
            // Lists that were turned off: free the space.
            dir.listFiles()?.forEach { f -> if (enabled.none { "${it.id}.txt" == f.name }) f.delete() }
            return Result(list.size, failed)
        } finally {
            progress = null
        }
    }

    private fun download(url: String, to: File) {
        val tmp = File(to.path + ".part")
        val c = URL(url).openConnection() as HttpURLConnection
        try {
            c.connectTimeout = 15000
            c.readTimeout = 60000
            c.setRequestProperty("User-Agent", "NetShield/1 (Android)")
            if (c.responseCode != 200) throw IOException("HTTP ${c.responseCode}")
            c.inputStream.use { i -> tmp.outputStream().use { o -> i.copyTo(o, 1 shl 16) } }
        } finally {
            c.disconnect()
        }
        if (tmp.length() < 100) {
            tmp.delete()
            throw IOException("empty list")
        }
        if (!tmp.renameTo(to)) {
            to.delete()
            if (!tmp.renameTo(to)) throw IOException("cannot save")
        }
    }

    companion object {
        const val STALE_MS = 3L * 24 * 3600 * 1000

        @Volatile
        private var shared: ListManager? = null

        /** One instance per process, so the app and the service never compile at once. */
        fun get(ctx: Context): ListManager = shared ?: synchronized(this) {
            shared ?: ListManager(ctx.applicationContext, ShieldPrefs(ctx)).also { shared = it }
        }
    }
}

/** uid → package name and app label, cached. */
class AppNames(ctx: Context) {
    private val pm: PackageManager = ctx.packageManager
    private val pkgs = ConcurrentHashMap<Int, String>()
    private val labels = ConcurrentHashMap<String, String>()

    fun pkg(uid: Int): String? {
        if (uid < 0) return null
        pkgs[uid]?.let { return it.ifEmpty { null } }
        val p = try {
            pm.getPackagesForUid(uid)?.sorted()?.firstOrNull()
        } catch (_: Exception) {
            null
        }
        pkgs[uid] = p ?: ""
        return p
    }

    fun label(pkg: String): String = labels.getOrPut(pkg) {
        try {
            pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
        } catch (_: Exception) {
            pkg
        }
    }

    fun isSystem(pkg: String): Boolean = try {
        pm.getApplicationInfo(pkg, 0).flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0
    } catch (_: Exception) {
        false
    }

    /** The app icon as a PNG of [size] px, or null. */
    fun iconPng(pkg: String, size: Int): ByteArray? = try {
        val d = pm.getApplicationIcon(pkg)
        val bmp = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
        val c = Canvas(bmp)
        d.setBounds(0, 0, size, size)
        d.draw(c)
        val out = ByteArrayOutputStream()
        bmp.compress(Bitmap.CompressFormat.PNG, 100, out)
        bmp.recycle()
        out.toByteArray()
    } catch (_: Exception) {
        null
    }
}
