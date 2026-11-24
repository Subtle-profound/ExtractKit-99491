package com.extractkit.app

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Android boot image 头解析（v0~v4）+ 内嵌 BTF 抽取。
 *
 * 只需要两件事：
 *   1. 从 boot.img 里把 arm64 的 kernel Image 切出来（KallsymsFinder 要扫它）
 *   2. Image 里通常内嵌 .BTF（magic 9f eb 01 00 18 00 00 00），直接切一段出来
 *
 * 设备上 shell 读不到 /sys/kernel/btf/vmlinux（SELinux），所以走 boot.img 这条路。
 */
object BootImage {

    data class Info(
        val headerVersion: Int,
        val kernelOffset: Long,
        val kernelSize: Int,
        val pageSize: Int,
    )

    private val MAGIC = "ANDROID!".toByteArray(Charsets.US_ASCII)
    private val VENDOR_MAGIC = "VNDRBOOT".toByteArray(Charsets.US_ASCII)
    private val ARM64_MAGIC = byteArrayOf('A'.code.toByte(), 'R'.code.toByte(), 'M'.code.toByte(), 0x64)

    class Unsupported(message: String) : Exception(message)

    /**
     * 9.410: 外层容器嗅探。
     *
     * 用户从网盘/刷机站拿到的 "boot.img" 经常不是 boot.img：整个文件是 zstd/gzip/lz4
     * 压缩流（首 4 字节就不是 ANDROID!），或者其实是 sparse / payload / zip。以前只报
     * 一句「magic 对不上 v0~v4」，用户只能猜。这里把容器认出来，交给调用方说清楚。
     */
    fun containerOf(head: ByteArray): String? {
        if (head.size < 6) return null
        fun at(i: Int, vararg sig: Int): Boolean =
            i + sig.size <= head.size && sig.indices.all { (head[i + it].toInt() and 0xFF) == sig[it] }
        return when {
            at(0, 0x28, 0xB5, 0x2F, 0xFD) -> "zstd"
            at(0, 0x1F, 0x8B) -> "gzip"
            at(0, 0x04, 0x22, 0x4D, 0x18) -> "lz4"
            at(0, 0x02, 0x21, 0x4C, 0x18) -> "lz4"
            at(0, 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00) -> "xz"
            at(0, 0x3A, 0xFF, 0x26, 0xED) -> "sparse"
            at(0, 0x50, 0x4B, 0x03, 0x04) -> "zip"
            at(0, 0x43, 0x72, 0x41, 0x55) -> "chromeos-payload"
            at(0, 0x4F, 0x54, 0x41, 0x21) -> "chromeos-payload"
            else -> null
        }
    }

    /** 给 UI 用的一句话解释（认不出返回通用文案）。 */
    fun containerHint(container: String): String = when (container) {
        "zstd" -> "这个文件整个是 zstd 压缩流（首 4 字节 28 b5 2f fd），不是 boot.img。先在电脑上解开：zstd -d 原文件 -o boot.img，再导入解出来的 boot.img"
        "gzip" -> "这个文件整个是 gzip 压缩流，不是 boot.img。先在电脑上解开（7-Zip / gzip -d）再导入"
        "lz4" -> "这个文件整个是 lz4 压缩流，不是 boot.img。先在电脑上 lz4 -d 解开再导入"
        "xz" -> "这个文件整个是 xz 压缩流，不是 boot.img。先在电脑上 xz -d 解开再导入"
        "sparse" -> "这是 Android sparse 镜像（散块格式），不是 boot.img。用 simg2img 转 raw 后再挑 boot.img"
        "zip" -> "这是一个 zip 包，不是 boot.img。先在电脑上解压，从里面挑 boot.img"
        "chromeos-payload" -> "这是 OTA payload（payload.bin），不是单分区镜像。用 payload-dumper-go 抽出 boot.img"
        else -> "不是可识别的 boot.img（magic 对不上 v0~v4）"
    }

    /** 返回 null 表示头不合法；抛 Unsupported 表示认得出但走不通（比如 vendor_boot）。 */
    fun parseHeader(head: ByteArray): Info? {
        if (head.size < 64) return null
        val buf = ByteBuffer.wrap(head).order(ByteOrder.LITTLE_ENDIAN)

        // 已经是裸 Image（有人直接把 kernel 存成 boot.img）
        if (head[0x38] == ARM64_MAGIC[0] && head[0x39] == ARM64_MAGIC[1] &&
            head[0x3A] == ARM64_MAGIC[2] && head[0x3B] == ARM64_MAGIC[3]
        ) {
            return Info(headerVersion = -1, kernelOffset = 0, kernelSize = head.size, pageSize = 4096)
        }

        if (!head.startsWith(MAGIC)) {
            if (head.startsWith(VENDOR_MAGIC)) throw Unsupported("这是 vendor_boot.img，请选 boot.img")
            return null
        }

        val kernelSize = buf.getInt(8)
        if (kernelSize <= 0) return null

        val headerVersion = buf.getInt(40)
        if (headerVersion in 3..4) {
            // v3/v4：kernel 固定在 4096 之后
            return Info(headerVersion, kernelOffset = 4096L, kernelSize = kernelSize, pageSize = 4096)
        }

        // v0~v2：page_size 在 36
        val pageSize = buf.getInt(36)
        if (pageSize in intArrayOf(2048, 4096, 8192, 16384, 32768, 65536)) {
            return Info(headerVersion, kernelOffset = pageSize.toLong(), kernelSize = kernelSize, pageSize = pageSize)
        }
        return null
    }

    /** 从输入流里按 Info 切出 kernel Image（只读需要的那一段，boot.img 整体可能有 100 MB）。 */
    fun readKernel(stream: java.io.FileInputStream, info: Info, maxBytes: Int = 64 * 1024 * 1024): ByteArray {
        val size = minOf(info.kernelSize, maxBytes)
        val out = ByteArray(size)
        stream.channel.position(info.kernelOffset)
        var read = 0
        while (read < size) {
            val n = stream.read(out, read, size - read)
            if (n <= 0) break
            read += n
        }
        return if (read == size) out else out.copyOf(read)
    }

    /**
     * 9.405: kernel 段可能是压缩的，扫 kallsyms / .BTF 之前必须先解开。
     * 返回 (字节, 用了哪种解压 or null)。
     */
    fun inflateKernel(image: ByteArray): Pair<ByteArray, String?> {
        if (image.size < 8) return image to null
        fun b(i: Int) = image[i].toInt() and 0xFF
        val lz4Legacy = b(0) == 0x02 && b(1) == 0x21 && b(2) == 0x4C && b(3) == 0x18
        val lz4Frame = b(0) == 0x04 && b(1) == 0x22 && b(2) == 0x4D && b(3) == 0x18
        if (lz4Legacy) return Lz4.legacy(image) to "lz4-legacy"
        if (lz4Frame) return Lz4.frame(image) to "lz4-frame"
        if (b(0) == 0x1F && b(1) == 0x8B) {
            val out = runCatching {
                java.util.zip.GZIPInputStream(image.inputStream(), 1 shl 16).use { it.readBytes() }
            }.getOrNull()
            if (out != null && out.isNotEmpty()) return out to "gzip"
        }
        if (b(0) == 0x28 && b(1) == 0xB5 && b(2) == 0x2F && b(3) == 0xFD) return image to "zstd (unsupported)"
        return image to null
    }

    /** Image 里的内核版本串，找不到就返回 null。 */
    fun kernelRelease(image: ByteArray): String? {
        val needle = "Linux version ".toByteArray(Charsets.US_ASCII)
        // 9.405: the plain string "Linux version %s" also lives in the image (a printf
        // format in the decompressor), so only accept a hit whose next byte is a digit.
        var from = 0
        while (true) {
            val at = indexOf(image, needle, from, image.size) ?: return null
            from = at + needle.size
            val first = at + needle.size
            if (first >= image.size) return null
            val c = image[first].toInt().toChar()
            if (c < '0' || c > '9') continue
            var end = first
            while (end < image.size && end - at < 200 && image[end] != 0.toByte()) end++
            val line = String(image, at, end - at, Charsets.ISO_8859_1)
            // "Linux version 6.6.118-... (kleaf@build-host) ..."
            val rel = line.removePrefix("Linux version ").substringBefore(' ')
            if (rel.isNotBlank()) return rel
        }
    }

    /** 在 Image 里找内嵌 BTF 并切出完整 BTF blob（header + types + strings）。 */
    fun extractBtf(image: ByteArray): ByteArray? {
        val magic = byteArrayOf(0x9f.toByte(), 0xeb.toByte(), 0x01, 0x00, 0x18, 0x00, 0x00, 0x00)
        val at = indexOf(image, magic, 0, image.size) ?: return null
        if (at + 24 > image.size) return null
        val buf = ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN)
        val hdrLen = buf.getInt(at + 4)
        val typeOff = buf.getInt(at + 8)
        val typeLen = buf.getInt(at + 12)
        val strOff = buf.getInt(at + 16)
        val strLen = buf.getInt(at + 20)
        if (hdrLen <= 0 || typeLen <= 0 || strLen <= 0) return null
        val total = hdrLen + maxOf(typeOff + typeLen, strOff + strLen)
        if (total <= 0 || at + total > image.size) return null
        return image.copyOfRange(at, at + total)
    }

    private fun indexOf(hay: ByteArray, needle: ByteArray, from: Int, to: Int): Int? {
        val limit = minOf(to, hay.size) - needle.size
        var i = from
        outer@ while (i <= limit) {
            for (j in needle.indices) {
                if (hay[i + j] != needle[j]) {
                    i++
                    continue@outer
                }
            }
            return i
        }
        return null
    }

    private fun ByteArray.startsWith(prefix: ByteArray): Boolean {
        if (size < prefix.size) return false
        for (i in prefix.indices) if (this[i] != prefix[i]) return false
        return true
    }
}
