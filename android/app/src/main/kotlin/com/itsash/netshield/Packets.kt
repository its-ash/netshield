package com.itsash.netshield

/**
 * Raw IPv4 / IPv6 packets as read from and written to the VPN interface:
 * parse the IP header, build a UDP reply, build a TCP reset. Pure Kotlin,
 * unit tested.
 */
object Packets {
    const val TCP = 6
    const val UDP = 17

    private const val FIN = 0x01
    private const val SYN = 0x02
    private const val RST = 0x04
    private const val ACK = 0x10

    /** An IP packet: addresses, transport protocol, and where its payload starts and ends. */
    class Ip(
        val v6: Boolean,
        val src: ByteArray,
        val dst: ByteArray,
        val proto: Int,
        val off: Int,
        val end: Int,
    )

    fun u16(b: ByteArray, i: Int): Int = ((b[i].toInt() and 0xff) shl 8) or (b[i + 1].toInt() and 0xff)

    private fun u32(b: ByteArray, i: Int): Long = (u16(b, i).toLong() shl 16) or u16(b, i + 2).toLong()

    private fun put16(b: ByteArray, i: Int, v: Int) {
        b[i] = (v ushr 8).toByte()
        b[i + 1] = v.toByte()
    }

    private fun put32(b: ByteArray, i: Int, v: Long) {
        put16(b, i, (v ushr 16).toInt() and 0xffff)
        put16(b, i + 2, v.toInt() and 0xffff)
    }

    /** Parses the IP header. Null for fragments, IPv6 extension headers and junk. */
    fun parse(b: ByteArray, len: Int): Ip? {
        if (len < 20) return null
        return when ((b[0].toInt() ushr 4) and 0x0f) {
            4 -> {
                val ihl = (b[0].toInt() and 0x0f) * 4
                val total = u16(b, 2)
                if (ihl < 20 || total < ihl || total > len) return null
                if (u16(b, 6) and 0x3fff != 0) return null // a fragment (MF set or offset > 0)
                Ip(false, b.copyOfRange(12, 16), b.copyOfRange(16, 20), b[9].toInt() and 0xff, ihl, total)
            }
            6 -> {
                if (len < 40) return null
                val end = 40 + u16(b, 4)
                if (end > len) return null
                Ip(true, b.copyOfRange(8, 24), b.copyOfRange(24, 40), b[6].toInt() and 0xff, 40, end)
            }
            else -> null
        }
    }

    /** One's complement sum of [len] bytes from [off], added to [start]. */
    private fun sum(b: ByteArray, off: Int, len: Int, start: Long = 0): Long {
        var s = start
        var i = off
        val end = off + len
        while (i + 1 < end) {
            s += u16(b, i)
            i += 2
        }
        if (i < end) s += (b[i].toInt() and 0xff) shl 8
        return s
    }

    private fun fold(s0: Long): Int {
        var s = s0
        while (s ushr 16 != 0L) s = (s and 0xffff) + (s ushr 16)
        return s.toInt().inv() and 0xffff
    }

    /** Writes the IP header for a [payloadLen] byte [proto] payload and returns its length. */
    private fun ipHeader(p: ByteArray, src: ByteArray, dst: ByteArray, proto: Int, payloadLen: Int): Int {
        if (src.size == 16) {
            p[0] = 0x60
            put16(p, 4, payloadLen)
            p[6] = proto.toByte()
            p[7] = 64
            System.arraycopy(src, 0, p, 8, 16)
            System.arraycopy(dst, 0, p, 24, 16)
            return 40
        }
        p[0] = 0x45
        put16(p, 2, 20 + payloadLen)
        put16(p, 6, 0x4000) // don't fragment
        p[8] = 64
        p[9] = proto.toByte()
        System.arraycopy(src, 0, p, 12, 4)
        System.arraycopy(dst, 0, p, 16, 4)
        put16(p, 10, fold(sum(p, 0, 20)))
        return 20
    }

    /** Checksum of a TCP or UDP segment with its IPv4 / IPv6 pseudo header. */
    private fun transportChecksum(p: ByteArray, src: ByteArray, dst: ByteArray, proto: Int, off: Int, len: Int): Int {
        var s = sum(src, 0, src.size)
        s = sum(dst, 0, dst.size, s)
        s += proto + len.toLong()
        return fold(sum(p, off, len, s))
    }

    /** A UDP packet from [src]:[srcPort] to [dst]:[dstPort] carrying [data]. */
    fun udp(src: ByteArray, dst: ByteArray, srcPort: Int, dstPort: Int, data: ByteArray): ByteArray {
        val ipLen = if (src.size == 16) 40 else 20
        val udpLen = 8 + data.size
        val p = ByteArray(ipLen + udpLen)
        ipHeader(p, src, dst, UDP, udpLen)
        put16(p, ipLen, srcPort)
        put16(p, ipLen + 2, dstPort)
        put16(p, ipLen + 4, udpLen)
        System.arraycopy(data, 0, p, ipLen + 8, data.size)
        var c = transportChecksum(p, src, dst, UDP, ipLen, udpLen)
        if (c == 0) c = 0xffff
        put16(p, ipLen + 6, c)
        return p
    }

    /**
     * A TCP reset answering the segment in [b] (RFC 793 reset rules), so an app
     * that tries encrypted DNS on a caught resolver fails at once and falls back
     * to plain DNS. Null when the segment is itself a reset.
     */
    fun tcpReset(b: ByteArray, ip: Ip): ByteArray? {
        val o = ip.off
        if (ip.end - o < 20) return null
        val srcPort = u16(b, o)
        val dstPort = u16(b, o + 2)
        val seq = u32(b, o + 4)
        val ack = u32(b, o + 8)
        val dataOff = ((b[o + 12].toInt() ushr 4) and 0x0f) * 4
        val flags = b[o + 13].toInt() and 0x3f
        if (flags and RST != 0) return null
        val segLen = (ip.end - o - dataOff).coerceAtLeast(0) +
            (if (flags and SYN != 0) 1 else 0) + (if (flags and FIN != 0) 1 else 0)
        val rSeq: Long
        val rAck: Long
        val rFlags: Int
        if (flags and ACK != 0) {
            rSeq = ack
            rAck = 0
            rFlags = RST
        } else {
            rSeq = 0
            rAck = (seq + segLen) and 0xffffffffL
            rFlags = RST or ACK
        }
        val ipLen = if (ip.v6) 40 else 20
        val p = ByteArray(ipLen + 20)
        ipHeader(p, ip.dst, ip.src, TCP, 20)
        put16(p, ipLen, dstPort)
        put16(p, ipLen + 2, srcPort)
        put32(p, ipLen + 4, rSeq)
        put32(p, ipLen + 8, rAck)
        p[ipLen + 12] = 0x50 // data offset 5 words
        p[ipLen + 13] = rFlags.toByte()
        put16(p, ipLen + 16, transportChecksum(p, ip.dst, ip.src, TCP, ipLen, 20))
        return p
    }

    /** True when the checksum of a built UDP/TCP packet verifies (used by tests). */
    fun verify(p: ByteArray): Boolean {
        val ip = parse(p, p.size) ?: return false
        if (!ip.v6 && fold(sum(p, 0, ip.off)) != 0) return false
        return transportChecksum(p, ip.src, ip.dst, ip.proto, ip.off, ip.end - ip.off) == 0
    }
}
