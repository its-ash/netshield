package com.itsash.netshield

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.util.concurrent.Executors

/** The settings UI's bridge to the VPN service (MethodChannel com.itsash.netshield/shield). */
class MainActivity : FlutterActivity() {
    private val bg = Executors.newCachedThreadPool()
    private val main = Handler(Looper.getMainLooper())
    private var pendingStart: MethodChannel.Result? = null

    private val prefs by lazy { ShieldPrefs(this) }
    private val apps by lazy { AppNames(this) }
    private val lists by lazy { ListManager.get(this) }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "com.itsash.netshield/shield")
            .setMethodCallHandler { call, result ->
                try {
                    handle(call, result)
                } catch (e: Exception) {
                    result.error("failed", e.message, null)
                }
            }
    }

    override fun onDestroy() {
        bg.shutdown()
        super.onDestroy()
    }

    /** Runs [task] off the main thread and answers on it. */
    private fun async(result: MethodChannel.Result, task: () -> Any?) {
        bg.execute {
            try {
                val v = task()
                main.post { result.success(v) }
            } catch (e: Exception) {
                main.post { result.error("failed", e.message ?: e.javaClass.simpleName, null) }
            }
        }
    }

    private fun handle(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "status" -> result.success(status())
            "start" -> {
                ShieldVpnService.lastError = null
                val ask = VpnService.prepare(this)
                if (ask == null) {
                    ShieldVpnService.start(this)
                    result.success(true)
                } else {
                    pendingStart?.success(false)
                    pendingStart = result
                    @Suppress("DEPRECATION")
                    startActivityForResult(ask, REQ_VPN)
                }
            }
            "stop" -> {
                ShieldVpnService.stop(this)
                result.success(null)
            }
            "setOption" -> {
                val value = call.argument<Any>("value")
                when (call.argument<String>("key")) {
                    "upstream" -> {
                        prefs.upstream = UpstreamProvider.of(value as String).key
                        ShieldVpnService.instance?.reloadRules()
                    }
                    "interceptDns" -> {
                        prefs.interceptDns = value as Boolean
                        ShieldVpnService.instance?.restart()
                    }
                }
                result.success(null)
            }
            "lists" -> result.success(
                ListCatalog.all.map { s ->
                    mapOf(
                        "id" to s.id,
                        "name" to s.name,
                        "description" to s.description,
                        "group" to s.group,
                        "recommended" to ListCatalog.defaultOn(s, Build.MANUFACTURER),
                        "enabled" to (s.id in prefs.enabledLists()),
                        "count" to prefs.listCount(s.id),
                    )
                },
            )
            "setListEnabled" -> {
                prefs.setListEnabled(call.argument<String>("id")!!, call.argument<Boolean>("on")!!)
                result.success(null)
            }
            "updateLists" -> async(result) {
                val r = lists.update(call.argument<Boolean>("force") ?: false)
                ShieldVpnService.instance?.reloadLists() ?: run { ShieldVpnService.filter.lists = lists.load() }
                mapOf("domains" to r.domains, "failed" to r.failed)
            }
            "log" -> {
                val after = (call.argument<Number>("after") ?: 0).toLong()
                val limit = call.argument<Int>("limit") ?: 500
                result.success(
                    ShieldVpnService.log.since(after, limit).map { e ->
                        mapOf(
                            "id" to e.id,
                            "time" to e.time,
                            "domain" to e.domain,
                            "type" to e.type,
                            "app" to QueryLog.appKey(e.uid, e.pkg),
                            "label" to label(QueryLog.appKey(e.uid, e.pkg)),
                            "verdict" to e.verdict,
                            "ms" to e.ms,
                            "detail" to e.detail,
                        )
                    },
                )
            }
            "clearLog" -> {
                ShieldVpnService.log.clear()
                result.success(null)
            }
            "appStats" -> {
                val bypass = prefs.bypass
                result.success(
                    ShieldVpnService.log.appCounts().map { (key, c) ->
                        mapOf(
                            "app" to key,
                            "label" to label(key),
                            "queries" to c[0],
                            "blocked" to c[1],
                            "bypass" to (key in bypass),
                        )
                    },
                )
            }
            "rules" -> {
                val r = prefs.rules()
                val appKeys = r.appAllow.keys + r.appBlock.keys
                result.success(
                    mapOf(
                        "allow" to r.allow.sorted(),
                        "block" to r.block.sorted(),
                        "apps" to appKeys.associateWith { k ->
                            mapOf(
                                "label" to label(k),
                                "allow" to (r.appAllow[k] ?: emptySet()).sorted(),
                                "block" to (r.appBlock[k] ?: emptySet()).sorted(),
                            )
                        },
                    ),
                )
            }
            "addRule" -> {
                val d = UserRules.normalize(call.argument<String>("domain") ?: "")
                if (d == null) {
                    result.error("domain", "Enter a domain such as ads.example.com.", null)
                    return
                }
                prefs.addRule(d, call.argument<Boolean>("allow")!!, call.argument<String>("app"))
                applyRules()
                result.success(d)
            }
            "removeRule" -> {
                prefs.removeRule(call.argument<String>("domain")!!, call.argument<Boolean>("allow")!!, call.argument<String>("app"))
                applyRules()
                result.success(null)
            }
            "check" -> async(result) {
                val d = UserRules.normalize(call.argument<String>("domain") ?: "") ?: return@async -1
                if (!ShieldVpnService.running && lists.ready) ShieldVpnService.filter.lists = lists.load()
                ShieldVpnService.filter.rules = prefs.rules()
                ShieldVpnService.filter.decide(d, call.argument<String>("app"))
            }
            "installedApps" -> async(result) {
                val bypass = prefs.bypass
                @Suppress("DEPRECATION")
                packageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS)
                    .filter { it.packageName != packageName && it.requestedPermissions?.contains(Manifest.permission.INTERNET) == true }
                    .map { p ->
                        mapOf(
                            "app" to p.packageName,
                            "label" to apps.label(p.packageName),
                            "system" to apps.isSystem(p.packageName),
                            "bypass" to (p.packageName in bypass),
                        )
                    }
                    .sortedBy { (it["label"] as String).lowercase() }
            }
            "setBypass" -> {
                val pkg = call.argument<String>("app")!!
                val on = call.argument<Boolean>("on")!!
                prefs.bypass = if (on) prefs.bypass + pkg else prefs.bypass - pkg
                ShieldVpnService.instance?.restart()
                result.success(null)
            }
            "appIcon" -> async(result) { apps.iconPng(call.argument<String>("app")!!, 96) }
            "openVpnSettings" -> {
                startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
                result.success(null)
            }
            "openNetworkSettings" -> {
                startActivity(Intent(Settings.ACTION_WIRELESS_SETTINGS))
                result.success(null)
            }
            "requestNotifications" -> {
                if (Build.VERSION.SDK_INT >= 33) requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 2)
                result.success(null)
            }
            else -> result.notImplemented()
        }
    }

    private fun applyRules() {
        ShieldVpnService.instance?.reloadRules() ?: run { ShieldVpnService.filter.rules = prefs.rules() }
    }

    /** Display name for a log app key: an app label, or what a system uid is. */
    private fun label(key: String): String = when {
        key == "unknown" -> "Unknown app"
        key.startsWith("uid:") -> when (val uid = key.removePrefix("uid:").toIntOrNull()) {
            0 -> "System (root)"
            1000 -> "Android system"
            1051 -> "Android DNS resolver"
            else -> "System process ($uid)"
        }
        else -> apps.label(key)
    }

    private fun status(): Map<String, Any?> {
        val (today, todayBlocked) = TodayStats.read(prefs)
        return mapOf(
            "running" to ShieldVpnService.running,
            "enabled" to prefs.enabled,
            "error" to ShieldVpnService.lastError,
            "listsReady" to lists.ready,
            "domains" to prefs.domainCount,
            "listsUpdatedAt" to prefs.listsUpdatedAt,
            "updating" to lists.progress,
            "upstream" to prefs.upstream,
            "interceptDns" to prefs.interceptDns,
            "privateDnsMode" to Settings.Global.getString(contentResolver, "private_dns_mode"),
            "privateDnsHost" to Settings.Global.getString(contentResolver, "private_dns_specifier"),
            "perApp" to (Build.VERSION.SDK_INT >= 29),
            "notifications" to (Build.VERSION.SDK_INT < 33 ||
                checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED),
            "today" to today,
            "todayBlocked" to todayBlocked,
        )
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQ_VPN) return
        val r = pendingStart ?: return
        pendingStart = null
        if (resultCode == RESULT_OK) {
            ShieldVpnService.start(this)
            r.success(true)
        } else {
            r.success(false)
        }
    }

    companion object {
        private const val REQ_VPN = 1
    }
}
