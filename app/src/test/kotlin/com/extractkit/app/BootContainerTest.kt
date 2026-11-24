package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/** 9.410: importing a compressed / non-boot container must be named, not reported as "magic 对不上". */
class BootContainerTest {

    private fun head(vararg b: Int, pad: Int = 64): ByteArray {
        val a = ByteArray(pad)
        for (i in b.indices) a[i] = b[i].toByte()
        return a
    }

    @Test
    fun namesTheContainer() {
        assertEquals("zstd", BootImage.containerOf(head(0x28, 0xB5, 0x2F, 0xFD)))
        assertEquals("gzip", BootImage.containerOf(head(0x1F, 0x8B, 0x08)))
        assertEquals("lz4", BootImage.containerOf(head(0x04, 0x22, 0x4D, 0x18)))
        assertEquals("lz4", BootImage.containerOf(head(0x02, 0x21, 0x4C, 0x18)))
        assertEquals("xz", BootImage.containerOf(head(0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00)))
        assertEquals("sparse", BootImage.containerOf(head(0x3A, 0xFF, 0x26, 0xED)))
        assertEquals("zip", BootImage.containerOf(head(0x50, 0x4B, 0x03, 0x04)))
        assertEquals("chromeos-payload", BootImage.containerOf(head(0x43, 0x72, 0x41, 0x55)))
        assertEquals("chromeos-payload", BootImage.containerOf(head(0x4F, 0x54, 0x41, 0x21)))
    }

    @Test
    fun leavesRealBootImagesAlone() {
        assertNull(BootImage.containerOf("ANDROID!".toByteArray(Charsets.US_ASCII) + ByteArray(56)))
        assertNull(BootImage.containerOf("VNDRBOOT".toByteArray(Charsets.US_ASCII) + ByteArray(56)))
        assertNull(BootImage.containerOf(ByteArray(8)))
    }

    @Test
    fun everyNamedContainerHasActionableText() {
        val kinds = listOf("zstd", "gzip", "lz4", "xz", "sparse", "zip", "chromeos-payload")
        for (k in kinds) {
            val t = BootImage.containerHint(k)
            assertNotNull(t)
            assertEquals(true, t.contains("boot.img"))
            assertEquals(false, t.contains("magic 对不上"))
        }
    }

    @Test
    fun unknownContainerFallsBack() {
        assertEquals(true, BootImage.containerHint("").startsWith("不是可识别的 boot.img"))
    }
}
