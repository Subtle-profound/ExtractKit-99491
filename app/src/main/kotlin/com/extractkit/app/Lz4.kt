package com.extractkit.app

/**
 * 9.405: 有些机型的 boot.img 里 kernel 段是压缩的（HONOR/高通系常见 legacy lz4 frame，
 * GKI 也有标准 lz4 frame 和 gzip）。标定要扫 kallsyms 和 .BTF，必须先把这一段解开。
 *
 * 只做解压，不做压缩；纯 Kotlin，无依赖（NDK 里没有 lz4，App 也不想为一个解压器塞 .so）。
 */
internal object Lz4 {

    /** 自增长输出缓冲；块解码可以回读已写出的字节（linked blocks）。 */
    private class Sink(capacity: Int) {
        var buf = ByteArray(capacity)
        var len = 0

        fun ensure(extra: Int) {
            val need = len + extra
            if (need <= buf.size) return
            var cap = buf.size
            while (cap < need) cap = if (cap < 1 shl 20) cap * 2 else cap + (cap shr 1)
            buf = buf.copyOf(cap)
        }

        fun finish(): ByteArray = buf.copyOf(len)
    }

    private fun le32(src: ByteArray, at: Int): Int =
        (src[at].toInt() and 0xFF) or
            ((src[at + 1].toInt() and 0xFF) shl 8) or
            ((src[at + 2].toInt() and 0xFF) shl 16) or
            ((src[at + 3].toInt() and 0xFF) shl 24)

    /** 解一个 LZ4 block，直接写进 sink（支持回读），返回写入长度。 */
    private fun decodeBlock(src: ByteArray, from: Int, to: Int, sink: Sink): Int {
        var ip = from
        val start = sink.len
        while (ip < to) {
            val token = src[ip++].toInt() and 0xFF
            var lit = token ushr 4
            if (lit == 15) {
                while (true) {
                    if (ip >= to) return sink.len - start
                    val b = src[ip++].toInt() and 0xFF
                    lit += b
                    if (b != 255) break
                }
            }
            if (lit > 0) {
                sink.ensure(lit)
                System.arraycopy(src, ip, sink.buf, sink.len, lit)
                sink.len += lit
                ip += lit
            }
            if (ip >= to) break
            if (ip + 1 >= to) break
            val offset = (src[ip].toInt() and 0xFF) or ((src[ip + 1].toInt() and 0xFF) shl 8)
            ip += 2
            var match = token and 0x0F
            if (match == 15) {
                while (true) {
                    if (ip >= to) break
                    val b = src[ip++].toInt() and 0xFF
                    match += b
                    if (b != 255) break
                }
            }
            match += 4
            if (offset <= 0 || offset > sink.len - start) return sink.len - start
            sink.ensure(match)
            var mp = sink.len - offset
            var remaining = match
            if (offset >= match) {
                System.arraycopy(sink.buf, mp, sink.buf, sink.len, match)
                sink.len += match
            } else {
                while (remaining-- > 0) sink.buf[sink.len++] = sink.buf[mp++]
            }
        }
        return sink.len - start
    }

    /** legacy frame: 0x184C2102 之后是一串 [le32 size][block]，size 高位置 1 表示未压缩。 */
    fun legacy(src: ByteArray): ByteArray {
        val sink = Sink(maxOf(src.size * 3, 1 shl 22))
        var ip = 4
        while (ip + 4 <= src.size) {
            val raw = le32(src, ip)
            ip += 4
            if (raw == 0) break
            val plain = raw and 0x7FFFFFFF
            if (plain <= 0 || ip + plain > src.size) break
            if (raw < 0) {
                sink.ensure(plain)
                System.arraycopy(src, ip, sink.buf, sink.len, plain)
                sink.len += plain
            } else {
                decodeBlock(src, ip, ip + plain, sink)
            }
            ip += plain
        }
        return sink.finish()
    }

    /** standard frame: 0x184D2204 + FLG/BD[/contentSize][/dictID]/HC，块同样 [le32 size]。 */
    fun frame(src: ByteArray): ByteArray {
        val sink = Sink(maxOf(src.size * 3, 1 shl 22))
        var ip = 4
        if (ip + 2 > src.size) return ByteArray(0)
        val flg = src[ip].toInt() and 0xFF
        ip += 2 // FLG + BD
        if (flg and 0x08 != 0) ip += 8 // content size
        if (flg and 0x01 != 0) ip += 4 // dict id
        ip += 1 // header checksum
        while (ip + 4 <= src.size) {
            val raw = le32(src, ip)
            ip += 4
            if (raw == 0) { // end mark
                if (flg and 0x04 != 0) ip += 4 // content checksum
                break
            }
            val plain = raw and 0x7FFFFFFF
            if (plain <= 0 || ip + plain > src.size) break
            if (raw < 0) {
                sink.ensure(plain)
                System.arraycopy(src, ip, sink.buf, sink.len, plain)
                sink.len += plain
            } else {
                decodeBlock(src, ip, ip + plain, sink)
            }
            ip += plain
        }
        return sink.finish()
    }
}
