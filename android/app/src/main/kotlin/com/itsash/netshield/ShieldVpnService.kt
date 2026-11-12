package com.itsash.netshield

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.service.quicksettings.TileService
import android.content.ComponentName
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import java.io.FileDescriptor
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.Executors

/**
 * The DNS-only VPN. Only the fake DNS server address (and, when "catch apps'
 * own DNS" is on, a list of public resolvers) is routed into the tunnel; all
 * other traffic goes straight to the network, so speed and battery are not
 * affected. Each query is checked against your rules and the lists, then
 * answered with 0.0.0.0 or forwarded over DNS-over-HTTPS.
 */
class ShieldVpnService : VpnService() {
    companion object {
        const val ACTION_START = "com.itsash.netshield.START"
        const val ACTION_STOP = "com.itsash.netshield.STOP"
        private const val CHANNEL = "shield"
        private const val NOTE_ID = 1

        private const val TUN_V4 = "10.111.222.1"
        private const val DNS_V4 = "10.111.222.2"
        private const val TUN_V6 = "fd00:6e73::1"
        private const val DNS_V6 = "fd00:6e73::2"

        /** Public resolvers apps use directly. Their port 53 is filtered, other ports are reset. */
        val HARDCODED_V4 = listOf(
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
            "9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10", "9.9.9.11", "149.112.112.11",
            "208.67.222.222", "208.67.220.220", "208.67.222.123", "208.67.220.123",
            "94.140.14.14", "94.140.15.15", "94.140.14.15", "94.140.15.16", "94.140.14.140", "94.140.14.141",
            "76.76.2.0", "76.76.10.0", "76.76.19.19", "76.223.122.150",
            "185.228.168.9", "185.228.169.9", "185.228.168.168", "185.228.169.168",
            "64.6.64.6", "64.6.65.6", "8.26.56.26", "8.20.247.20", "77.88.8.8", "77.88.8.1",
            "223.5.5.5", "223.6.6.6", "119.29.29.29", "180.76.76.76", "114.114.114.114", "114.114.115.115",
            "45.90.28.0", "45.90.30.0", "194.242.2.2", "86.54.11.1", "86.54.11.100",
        )
        val HARDCODED_V6 = listOf(
            "2001:4860:4860::8888", "2001:4860:4860::8844",
            "2606:4700:4700::1111", "2606:4700:4700::1001", "2606:4700:4700::1112", "2606:4700:4700::1002",
            "2620:fe::fe", "2620:fe::9", "2620:fe::10", "2620:fe::11",
            "2620:119:35::35", "2620:119:53::53",
            "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff", "2a10:50c0::1:ff", "2a10:50c0::2:ff",
            "2a07:a8c0::", "2a07:a8c1::", "2a07:e340::2",
        )

        @Volatile
        var instance: ShieldVpnService? = null
            private set

        /** Why the last start failed, shown in the app. */
        @Volatile
        var lastError: String? = null

        val log = QueryLog()
        val filter = DnsFilter()

        val running: Boolean get() = instance?.tun != null

        fun start(ctx: Context) {
            ctx.startForegroundService(Intent(ctx, ShieldVpnService::class.java).setAction(ACTION_START))
        }

        /** Stops protection and remembers that the user turned it off. */
        fun stop(ctx: Context) {
            ShieldPrefs(ctx).enabled = false
            instance?.shutdown() ?: ctx.stopService(Intent(ctx, ShieldVpnService::class.java))
        }
    }

    @Volatile
    private var tun: ParcelFileDescriptor? = null
    private var wakeRead: FileDescriptor? = null
    private var wakeWrite: FileDescriptor? = null
    private var reader: Thread? = null

    private lateinit var prefs: ShieldPrefs
    private lateinit var apps: AppNames
    lateinit var lists: ListManager
        private set

    private val queries = Executors.newFixedThreadPool(8)
    private val work = Executors.newSingleThreadExecutor()
    private val cache = DnsCache()
    private val main = Handler(Looper.getMainLooper())
    private val writeLock = Any()

    @Volatile
    private var upstream = Upstream(UpstreamProvider.DEFAULT)

    private val tick = object : Runnable {
        override fun run() {
            if (tun == null) return
            TodayStats.save(prefs)
            notifyManager().notify(NOTE_ID, notification())
            NetShieldWidget.updateThrottled(this@ShieldVpnService)
            main.postDelayed(this, 15_000)
        }
    }

    override fun onCreate() {
        super.onCreate()
        prefs = ShieldPrefs(this)
        apps = AppNames(this)
        lists = ListManager.get(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            prefs.enabled = false
            shutdown()
            return START_NOT_STICKY
        }
        createChannel()
        startForeground(NOTE_ID, notification())
        if (prepare(this) != null) {
            lastError = "Allow the VPN request to turn NetShield on."
            shutdown()
            return START_NOT_STICKY
        }
        prefs.enabled = true
        work.execute { startVpn() }
        return START_STICKY
    }

    override fun onRevoke() {
        // Another VPN took over, or the user turned NetShield off in Android settings.
        prefs.enabled = false
        lastError = "NetShield was turned off by Android or by another VPN app."
        shutdown()
    }

    override fun onDestroy() {
        closeTun()
        if (instance === this) instance = null
        TodayStats.save(prefs)
        queries.shutdownNow()
        work.shutdownNow()
        main.removeCallbacksAndMessages(null)
        refreshTile()
        NetShieldWidget.updateAll(this)
        super.onDestroy()
    }

    /** Stops the tunnel and the service. */
    fun shutdown() {
        closeTun()
        if (instance === this) instance = null
        TodayStats.save(prefs)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        refreshTile()
        NetShieldWidget.updateAll(this)
    }

    /** New rules or upstream: applies at once, no reconnect. */
    fun reloadRules() {
        filter.rules = prefs.rules()
        upstream = Upstream(UpstreamProvider.of(prefs.upstream))
        cache.clear()
    }

    /** New compiled lists. */
    fun reloadLists() {
        filter.lists = lists.load()
        cache.clear()
    }

    /** Settings that change the tunnel itself (bypassed apps, resolver catching). */
    fun restart() {
        work.execute {
            closeTun()
            startVpn()
        }
    }

    @Synchronized
    private fun startVpn() {
        if (tun != null) return
        filter.lists = lists.load()
        reloadRules()
        val b = Builder()
            .setSession("NetShield")
            .setMtu(1500)
            .setBlocking(false)
            .addAddress(TUN_V4, 32)
            .addDnsServer(DNS_V4)
            .addRoute(DNS_V4, 32)
        try {
            b.addAddress(TUN_V6, 128).addDnsServer(DNS_V6).addRoute(DNS_V6, 128)
        } catch (_: Exception) {
        }
        if (prefs.interceptDns) {
            for (ip in HARDCODED_V4) runCatching { b.addRoute(ip, 32) }
            for (ip in HARDCODED_V6) runCatching { b.addRoute(ip, 128) }
        }
        // NetShield's own traffic (DoH upstream, list downloads) must not loop back in.
        try {
            b.addDisallowedApplication(packageName)
        } catch (_: PackageManager.NameNotFoundException) {
        }
        for (p in prefs.bypass) {
            try {
                b.addDisallowedApplication(p)
            } catch (_: PackageManager.NameNotFoundException) {
            }
        }
        if (Build.VERSION.SDK_INT >= 29) b.setMetered(false)
        b.setConfigureIntent(
            PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE),
        )
        val fd = try {
            b.establish()
        } catch (e: Exception) {
            lastError = "Android refused the VPN: ${e.message}"
            null
        }
        if (fd == null) {
            if (lastError == null) lastError = "Android refused the VPN. Allow NetShield in VPN settings."
            main.post { shutdown() }
            return
        }
        val pipe = Os.pipe()
        wakeRead = pipe[0]
        wakeWrite = pipe[1]
        tun = fd
        instance = this
        lastError = null
        reader = Thread({ readLoop(fd, pipe[0]) }, "netshield-tun").also { it.start() }
        main.post {
            notifyManager().notify(NOTE_ID, notification())
            main.removeCallbacks(tick)
            main.postDelayed(tick, 15_000)
            refreshTile()
            NetShieldWidget.updateAll(this)
        }
        if (!lists.ready || lists.stale) {
            try {
                lists.update(force = false)
                reloadLists()
            } catch (_: Exception) {
            }
        }
    }

    private fun closeTun() {
        val fd = tun ?: return
        tun = null
        wakeWrite?.let { runCatching { Os.write(it, byteArrayOf(1), 0, 1) } }
        reader?.join(1000)
        reader = null
        runCatching { fd.close() }
        wakeRead?.let { runCatching { Os.close(it) } }
        wakeWrite?.let { runCatching { Os.close(it) } }
        wakeRead = null
        wakeWrite = null
        cache.clear()
    }

    private fun readLoop(fd: ParcelFileDescriptor, wake: FileDescriptor) {
        val tunFd = fd.fileDescriptor
        val buf = ByteArray(32767)
        val polls = arrayOf(StructPollfd(), StructPollfd())
        polls[0].fd = tunFd
        polls[0].events = OsConstants.POLLIN.toShort()
        polls[1].fd = wake
        polls[1].events = OsConstants.POLLIN.toShort()
        while (tun === fd) {
            try {
                Os.poll(polls, -1)
            } catch (e: ErrnoException) {
                if (e.errno == OsConstants.EINTR) continue
                break
            }
            if (polls[1].revents.toInt() != 0 || tun !== fd) break
            if (polls[0].revents.toInt() and OsConstants.POLLIN == 0) {
                if (polls[0].revents.toInt() != 0) break // POLLERR / POLLHUP: interface gone
                continue
            }
            // Drain everything that is waiting.
            while (true) {
                val n = try {
                    Os.read(tunFd, buf, 0, buf.size)
                } catch (e: ErrnoException) {
                    if (e.errno == OsConstants.EAGAIN) break
                    return
                } catch (_: IOException) {
                    return
                }
                if (n <= 0) break
                handle(buf.copyOf(n))
            }
        }
    }

    private fun handle(pkt: ByteArray) {
        val ip = Packets.parse(pkt, pkt.size) ?: return
        when (ip.proto) {
            Packets.UDP -> {
                if (ip.end - ip.off < 8) return
                if (Packets.u16(pkt, ip.off + 2) != 53) return // QUIC / DoQ to a caught resolver: dropped
                try {
                    queries.execute { answer(pkt, ip) }
                } catch (_: Exception) {
                }
            }
            // DoH / DoT straight to a caught resolver, or DNS over TCP: reset so the app falls back to UDP DNS.
            Packets.TCP -> Packets.tcpReset(pkt, ip)?.let { write(it) }
        }
    }

    private fun answer(pkt: ByteArray, ip: Packets.Ip) {
        val t0 = SystemClock.elapsedRealtime()
        val srcPort = Packets.u16(pkt, ip.off)
        val dstPort = Packets.u16(pkt, ip.off + 2)
        val dns = pkt.copyOfRange(ip.off + 8, ip.end)
        val q = DnsMessage.parseQuery(dns) ?: return
        val uid = ownerUid(ip, srcPort, dstPort)
        val pkg = apps.pkg(uid)
        var verdict = filter.decide(q.name, pkg)
        var detail: String? = null
        var resp: ByteArray
        if (Verdict.blocked(verdict)) {
            resp = DnsMessage.blockedResponse(dns, q)
        } else {
            val now = System.currentTimeMillis()
            val cached = cache.get(q.name, q.type, now)
            var r: ByteArray? = cached?.let { DnsMessage.withId(it, q.id) }
            if (r == null) {
                r = try {
                    upstream.resolve(dns)
                } catch (e: IOException) {
                    verdict = Verdict.ERROR
                    detail = e.message
                    null
                }
            }
            if (r == null) {
                resp = DnsMessage.servfail(dns, q)
            } else {
                resp = r
                val a = DnsMessage.parseAnswer(r)
                if (a != null) {
                    // CNAME uncloaking: a tracker hidden behind a first-party name.
                    val cloaked = if (verdict == Verdict.ALLOWED) {
                        a.cnames.firstOrNull { Verdict.blocked(filter.decide(it, pkg)) }
                    } else {
                        null
                    }
                    if (cloaked != null) {
                        verdict = Verdict.BLOCKED_CNAME
                        detail = cloaked
                        resp = DnsMessage.blockedResponse(dns, q)
                    } else {
                        if (a.nullAnswer && verdict == Verdict.ALLOWED) verdict = Verdict.BLOCKED_UPSTREAM
                        detail = a.ips.firstOrNull() ?: a.cnames.lastOrNull()
                    }
                    if (cached == null && (a.rcode == 0 || a.rcode == 3)) cache.put(q.name, q.type, r, a.minTtl, now)
                }
            }
        }
        write(Packets.udp(ip.dst, ip.src, dstPort, srcPort, resp))
        log.add(System.currentTimeMillis(), q.name, q.type, uid, pkg, verdict, (SystemClock.elapsedRealtime() - t0).toInt(), detail)
        TodayStats.count(prefs, Verdict.blocked(verdict))
    }

    /** The app that sent this query (Android 10+; the VPN owner may ask). */
    private fun ownerUid(ip: Packets.Ip, srcPort: Int, dstPort: Int): Int {
        if (Build.VERSION.SDK_INT < 29) return -1
        return try {
            val cm = getSystemService(ConnectivityManager::class.java)
            cm.getConnectionOwnerUid(
                OsConstants.IPPROTO_UDP,
                InetSocketAddress(InetAddress.getByAddress(ip.src), srcPort),
                InetSocketAddress(InetAddress.getByAddress(ip.dst), dstPort),
            )
        } catch (_: Exception) {
            -1
        }
    }

    private fun write(p: ByteArray) {
        val fd = tun ?: return
        synchronized(writeLock) {
            try {
                Os.write(fd.fileDescriptor, p, 0, p.size)
            } catch (_: Exception) {
                // Interface closed or queue full: the app's resolver retries.
            }
        }
    }

    private fun notifyManager() = getSystemService(NotificationManager::class.java)

    private fun createChannel() {
        notifyManager().createNotificationChannel(
            NotificationChannel(CHANNEL, "Protection status", NotificationManager.IMPORTANCE_LOW).apply {
                description = "Shown while NetShield blocks ads."
                setShowBadge(false)
            },
        )
    }

    private fun notification(): Notification {
        val (total, blocked) = TodayStats.read(prefs)
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(
            this, 1, Intent(this, ShieldVpnService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE,
        )
        val text = if (tun == null) "Starting…" else "Blocked $blocked of $total requests today"
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setContentTitle("NetShield is on")
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .addAction(Notification.Action.Builder(null, "Turn off", stop).build())
            .build()
    }

    private fun refreshTile() {
        runCatching {
            TileService.requestListeningState(this, ComponentName(this, ShieldTileService::class.java))
        }
    }
}
