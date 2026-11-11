package com.itsash.netshield

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL

/**
 * Where allowed queries go. NetShield itself is excluded from its VPN, so these
 * connections use the phone's real network and cannot loop back into the tunnel.
 */
enum class UpstreamProvider(val key: String, val label: String, val dohUrl: String, val plainIp: String) {
    ADGUARD("adguard", "AdGuard DNS", "https://dns.adguard-dns.com/dns-query", "94.140.14.14"),
    CLOUDFLARE("cloudflare", "Cloudflare", "https://cloudflare-dns.com/dns-query", "1.1.1.1"),
    QUAD9("quad9", "Quad9", "https://dns.quad9.net/dns-query", "9.9.9.9"),
    GOOGLE("google", "Google", "https://dns.google/dns-query", "8.8.8.8"),
    ;

    companion object {
        val DEFAULT = ADGUARD
        fun of(key: String?) = entries.firstOrNull { it.key == key } ?: DEFAULT
    }
}

/**
 * Resolves a raw DNS query: DNS over HTTPS (RFC 8484) first, so the network
 * cannot read or change answers, then plain UDP to the same provider if HTTPS
 * fails (captive portals, blocked port 443).
 */
class Upstream(val provider: UpstreamProvider) {
    fun resolve(query: ByteArray): ByteArray {
        try {
            return doh(query)
        } catch (e: IOException) {
            try {
                return udp(query)
            } catch (e2: IOException) {
                throw IOException("${provider.label}: ${e.message ?: e.javaClass.simpleName}", e2)
            }
        }
    }

    private fun doh(query: ByteArray): ByteArray {
        // RFC 8484: id 0 lets HTTP caches share answers. Restore the id after.
        val id = DnsMessage.u16(query, 0)
        val body = query.copyOf()
        DnsMessage.setId(body, 0)
        val c = URL(provider.dohUrl).openConnection() as HttpURLConnection
        var ok = false
        try {
            c.requestMethod = "POST"
            c.connectTimeout = 4000
            c.readTimeout = 4000
            c.doOutput = true
            c.useCaches = false
            c.setRequestProperty("Content-Type", "application/dns-message")
            c.setRequestProperty("Accept", "application/dns-message")
            c.setFixedLengthStreamingMode(body.size)
            c.outputStream.use { it.write(body) }
            if (c.responseCode != 200) throw IOException("HTTP ${c.responseCode}")
            val out = ByteArrayOutputStream()
            c.inputStream.use { it.copyTo(out) }
            val resp = out.toByteArray()
            if (resp.size < 12) throw IOException("short answer")
            DnsMessage.setId(resp, id)
            ok = true
            return resp
        } finally {
            // Keep-alive: a fully read body returns the connection to the pool.
            // Drop it after any failure so a broken connection is not reused.
            if (!ok) c.disconnect()
        }
    }

    private fun udp(query: ByteArray): ByteArray {
        DatagramSocket().use { s ->
            s.soTimeout = 3000
            val addr = InetAddress.getByName(provider.plainIp)
            s.send(DatagramPacket(query, query.size, addr, 53))
            val buf = ByteArray(4096)
            val p = DatagramPacket(buf, buf.size)
            s.receive(p)
            return buf.copyOf(p.length)
        }
    }
}
