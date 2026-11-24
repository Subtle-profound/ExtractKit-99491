package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Test

class Lz4Test {

    private fun le32(v: Int) = byteArrayOf(
        (v and 0xFF).toByte(),
        ((v ushr 8) and 0xFF).toByte(),
        ((v ushr 16) and 0xFF).toByte(),
        ((v ushr 24) and 0xFF).toByte(),
    )

    @Test
    fun legacyFrameWithLiteralsOnly() {
        // token 0x40 = 4 literals, no match
        val block = byteArrayOf(0x40) + "abcd".toByteArray()
        val frame = byteArrayOf(0x02, 0x21, 0x4C, 0x18) + le32(block.size) + block + le32(0)
        assertEquals("abcd", String(Lz4.legacy(frame)))
    }

    @Test
    fun legacyFrameWithMatch() {
        // token 0x40 = 4 literals + match nibble 0 (=> 4 bytes copied), offset 4
        val block = byteArrayOf(0x40) + "abcd".toByteArray() + byteArrayOf(0x04, 0x00)
        val frame = byteArrayOf(0x02, 0x21, 0x4C, 0x18) + le32(block.size) + block + le32(0)
        assertEquals("abcdabcd", String(Lz4.legacy(frame)))
    }

    @Test
    fun standardFrameLiterals() {
        val block = byteArrayOf(0x40) + "wxyz".toByteArray()
        val frame = byteArrayOf(0x04, 0x22, 0x4D, 0x18, 0x60, 0x40, 0x00) + le32(block.size) + block + le32(0)
        assertEquals("wxyz", String(Lz4.frame(frame)))
    }
}
