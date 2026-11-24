package com.extractkit.app

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import java.io.BufferedInputStream
import java.io.File
import java.io.InputStream
import java.util.zip.GZIPInputStream

/**
 * 9.411: 标定入口自带解压。
 *
 * 刷机站 / 网盘给的 "boot.img" 常常是整文件压缩过的（zstd 最常见），以前只能让用户去电脑上
 * 解一层再导回来。这里直接在 App 里把整文件容器剥掉，落一份 raw 镜像到 cache，再按原来的
 * boot 头解析。只处理「整个文件就是一个流」的容器；zip / payload.bin 要挑分区，仍交给电脑。
 */
object ImageUnpack {

    /** 单个镜像上限：真机 boot.img 一般 < 100 MB，留足余量又不至于把手机写满。 */
    private const val MAX_UNPACK = 512L * 1024 * 1024

    fun canUnpack(container: String): Boolean =
        container == "zstd" || container == "gzip" || container == "lz4" || container == "sparse"

    fun outputFile(context: Context): File = File(context.cacheDir, "boot-unpacked.img")

    /**
     * 把 uri 解成 raw 镜像写到 cache，返回文件；失败返回 null。
     * zstd / gzip 走流式（边解边写，不吃内存），lz4 / sparse 在内存里解（这两种体积本来就不大）。
     */
    fun unpack(
        context: Context,
        resolver: ContentResolver,
        uri: Uri,
        container: String,
        log: (String) -> Unit,
    ): File? {
        val out = outputFile(context)
        out.delete()
        return try {
            when (container) {
                "zstd" -> pump(resolver, uri, out, container, log) { i ->
                    io.airlift.compress.zstd.ZstdInputStream(BufferedInputStream(i, 1 shl 16))
                }
                "gzip" -> pump(resolver, uri, out, container, log) { i -> GZIPInputStream(i, 1 shl 16) }
                "lz4" -> {
                    val all = resolver.openInputStream(uri)!!.use { it.readBytes() }
                    val raw = if ((all[0].toInt() and 0xFF) == 0x04) Lz4.frame(all) else Lz4.legacy(all)
                    if (raw == null || raw.size < 4096) {
                        out.delete()
                        null
                    } else {
                        out.writeBytes(raw)
                        log("解压出 " + (raw.size / 1024 / 1024) + " MiB (lz4)")
                        out
                    }
                }
                "sparse" -> {
                    val all = resolver.openInputStream(uri)!!.use { it.readBytes() }
                    val raw = Sparse.expand(all)
                    if (raw == null || raw.size < 4096) {
                        out.delete()
                        null
                    } else {
                        out.writeBytes(raw)
                        log("sparse 展开成 " + (raw.size / 1024 / 1024) + " MiB")
                        out
                    }
                }
                else -> null
            }
        } catch (t: Throwable) {
            // Unsafe / 类加载 / 解压器内部错误都兜在这里：退回「请在电脑上解一层」的提示
            log("! 解压失败：" + t.javaClass.simpleName + ": " + t.message)
            out.delete()
            null
        }
    }

    private inline fun pump(
        resolver: ContentResolver,
        uri: Uri,
        out: File,
        container: String,
        log: (String) -> Unit,
        wrap: (InputStream) -> InputStream,
    ): File? {
        var total = 0L
        var truncated = false
        resolver.openInputStream(uri)!!.use { raw ->
            val input = wrap(raw)
            out.outputStream().use { o ->
                val buf = ByteArray(1 shl 20)
                while (true) {
                    val n = try {
                        input.read(buf, 0, buf.size)
                    } catch (t: Throwable) {
                        // 容器后面还挂着非压缩数据（截断的下载很常见）：保留已经解出来的部分
                        truncated = true
                        -1
                    }
                    if (n < 0) break
                    o.write(buf, 0, n)
                    total += n
                    if (total > MAX_UNPACK) {
                        truncated = true
                        break
                    }
                }
            }
        }
        log(
            "解压出 " + (total / 1024 / 1024) + " MiB (" + container + ")" +
                if (truncated) "，容器尾部有非压缩数据，已提前结束" else "",
        )
        return if (total >= 4096) out else {
            out.delete()
            null
        }
    }
}

/**
 * Android sparse 镜像 -> raw（simg2img 的最小实现）。
 * 只读 chunk：RAW / FILL / DONT_CARE / CRC32，覆盖 fastboot 与厂商工具产出的镜像足够。
 */
object Sparse {

    fun expand(src: ByteArray): ByteArray? {
        if (src.size < 28) return null
        fun u32(at: Int) = (src[at].toInt() and 0xFF) or
            ((src[at + 1].toInt() and 0xFF) shl 8) or
            ((src[at + 2].toInt() and 0xFF) shl 16) or
            ((src[at + 3].toInt() and 0xFF) shl 24)
        fun u16(at: Int) = (src[at].toInt() and 0xFF) or ((src[at + 1].toInt() and 0xFF) shl 8)
        // sparse_header: magic@0, major@4(u16), minor@6(u16), file_hdr_sz@8(u16),
        // chunk_hdr_sz@10(u16), blk_sz@12(u32), total_blks@16(u32), total_chunks@20, checksum@24
        if (u32(0) != 0xED26FF3A.toInt()) return null
        if (u16(4) != 0) return null
        val fileHdrSize = u16(8)
        val chunkHdrSize = u16(10)
        val blkSize = u32(12)
        val totalBlks = u32(16)
        if (blkSize !in intArrayOf(4096, 8192, 16384, 32768, 65536)) return null
        if (totalBlks <= 0 || totalBlks.toLong() * blkSize > 512L * 1024 * 1024) return null

        val out = ByteArray(totalBlks * blkSize)
        var pos = fileHdrSize
        var written = 0
        while (pos + chunkHdrSize <= src.size) {
            // chunk_header: type@0, chunk_sz@4(块数), total_sz@8(含头的字节数), crc@12
            val type = u32(pos)
            val chunkBlocks = u32(pos + 4)
            val totalSize = u32(pos + 8)
            val body = pos + chunkHdrSize
            val bytes = chunkBlocks.toLong() * blkSize
            if (written + bytes > out.size) return null
            when (type) {
                0xCAC1 -> { // raw
                    if (body + bytes > src.size) return null
                    System.arraycopy(src, body, out, written, bytes.toInt())
                }
                0xCAC2 -> { // fill：整块用 4 字节循环填充
                    if (body + 4 > src.size) return null
                    val v = byteArrayOf(src[body], src[body + 1], src[body + 2], src[body + 3])
                    var at = written
                    while (at < written + bytes) {
                        out[at] = v[(at - written) and 3]
                        at++
                    }
                }
                0xCAC3, 0xCAC4 -> { /* don't care / crc32：保持零 */ }
                else -> return null
            }
            written += bytes.toInt()
            pos += totalSize
            if (chunkBlocks == 0 || totalSize == 0) break
        }
        return if (written > 0) out else null
    }
}
