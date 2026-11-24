package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

/**
 * 9.411: 标定入口自带解压 —— 只测纯 JVM 能跑的部分（容器判定 / sparse 展开 / zstd 流解码）。
 * ContentResolver 相关路径要真机才能走，靠 chk9411.py 与真机导入验证。
 */
class BootUnpackTest {

    @Test
    fun canUnpackCoversTheFourStreamsWeDecode() {
        assertTrue(ImageUnpack.canUnpack("zstd"))
        assertTrue(ImageUnpack.canUnpack("gzip"))
        assertTrue(ImageUnpack.canUnpack("lz4"))
        assertTrue(ImageUnpack.canUnpack("sparse"))
    }

    @Test
    fun canUnpackRejectsContainersThatNeedAPc() {
        assertFalse(ImageUnpack.canUnpack("xz"))
        assertFalse(ImageUnpack.canUnpack("zip"))
        assertFalse(ImageUnpack.canUnpack("payload"))
        assertFalse(ImageUnpack.canUnpack(""))
        assertFalse(ImageUnpack.canUnpack("raw"))
    }

    @Test
    fun zstdStreamDecodesAWholeFileFrame() {
        // 真机上 zstd 走 io.airlift.compress.zstd.ZstdInputStream；这里验证依赖能用、且头 8 字节还原正确
        val body = ByteArray(256 * 1024)
        "ANDROID!".toByteArray(Charsets.US_ASCII).copyInto(body, 0)
        for (i in 8 until body.size) body[i] = (i % 251).toByte()
        val packed = ByteArrayOutputStream().also { out ->
            io.airlift.compress.zstd.ZstdOutputStream(out).use { it.write(body) }
        }.toByteArray()
        assertTrue("zstd magic", packed[0] == 0x28.toByte() && packed[1] == 0xB5.toByte())
        val back = io.airlift.compress.zstd.ZstdInputStream(ByteArrayInputStream(packed))
            .use { it.readBytes() }
        assertEquals(body.size, back.size)
        assertEquals("ANDROID!", String(back, 0, 8, Charsets.US_ASCII))
    }

    @Test
    fun sparseExpandsRawAndFillChunks() {
        // 最小 sparse：1 个 4096 字节块，先 raw 再 fill，总 2 块
        val blk = 4096
        val out = ByteArray(2 * blk)
        val chunk = 16 // chunk_header 是 4 个 u32
        val buf = ByteArrayOutputStream()
        fun u32(v: Int) {
            buf.write(v and 0xFF); buf.write((v ushr 8) and 0xFF)
            buf.write((v ushr 16) and 0xFF); buf.write((v ushr 24) and 0xFF)
        }
        fun u16(v: Int) {
            buf.write(v and 0xFF); buf.write((v ushr 8) and 0xFF)
        }
        // 真实布局：magic u32, major u16, minor u16, file_hdr_sz u16, chunk_hdr_sz u16,
        // blk_sz u32, total_blks u32, total_chunks u32, checksum u32
        u32(0xED26FF3A.toInt()); u16(0); u16(0); u16(28); u16(chunk)
        u32(blk); u32(2); u32(2); u32(0)
        // raw chunk：1 块，body 4096 字节
        u32(0xCAC1); u32(1); u32(chunk + blk); u32(0)
        buf.write(ByteArray(blk) { 0x41 })
        // fill chunk：1 块，填 4 个字节
        u32(0xCAC2); u32(1); u32(chunk + 4); u32(0)
        buf.write(byteArrayOf(1, 2, 3, 4))
        val expanded = Sparse.expand(buf.toByteArray())
        assertNotNull(expanded)
        assertEquals(2 * blk, expanded!!.size)
        assertEquals(0x41.toByte(), expanded[0])
        assertEquals(0x41.toByte(), expanded[blk - 1])
        assertEquals(1.toByte(), expanded[blk])
        assertEquals(4.toByte(), expanded[blk + 3])
        assertEquals(1.toByte(), expanded[blk + 4])
    }

    @Test
    fun sparseRejectsNonSparseBytes() {
        assertNull(Sparse.expand(ByteArray(64) { 0x41 }))
        assertNull(Sparse.expand(ByteArray(4)))
    }
}
