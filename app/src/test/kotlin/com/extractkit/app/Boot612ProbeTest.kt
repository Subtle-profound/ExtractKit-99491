package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * 回归测试：用户提供的 6.12.58 gdf8d34 boot.img 上，CallSiteFinder 必须解出三处 site。
 * 机器上没有这颗镜像时直接跳过。
 */
class Boot612ProbeTest {

    // Skipped unless the user-provided image exists on this machine.
    private fun img(): ByteArray? {
        val f = java.io.File("C:/Users/Admin/Downloads/boot.img")
        return if (f.exists()) f.readBytes() else null
    }

    @Test
    fun sites() {
        val raw = img() ?: return
        val info = BootImage.parseHeader(raw.copyOfRange(0, 4096))!!
        println("[p] kernel at " + info.kernelOffset + " size " + info.kernelSize)
        val image = raw.copyOfRange(info.kernelOffset.toInt(), info.kernelOffset.toInt() + info.kernelSize)
        println("[p] release=" + BootImage.kernelRelease(image))
        val found = KallsymsFinder.find(image)!!
        println("[p] syms=" + found.symbols.size)
        val r = CallSiteFinder.find(image, found.symbols, found.relativeBase)!!
        println("[p] timer low21=0x" + Integer.toHexString(r.timerLow21) + " abs=0x" + java.lang.Long.toHexString(r.timerAbs))
        println("[p] cred  low21=0x" + Integer.toHexString(r.credLow21) + " abs=0x" + java.lang.Long.toHexString(r.credAbs))
        println("[p] task  low21=0x" + Integer.toHexString(r.taskLow21) + " abs=0x" + java.lang.Long.toHexString(r.taskAbs))
        r.detail.forEach { println("[p] " + it) }
        assertEquals(0x117bec, r.timerLow21)
        assertEquals(0x19b1fc, r.credLow21)
        assertEquals(0x1f2938, r.taskLow21)
    }
}