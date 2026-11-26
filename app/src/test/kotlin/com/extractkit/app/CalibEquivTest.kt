package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.io.FileInputStream

/**
 * 用官方 boot.img 跑一遍 App 自己的标定流水线（KallsymsFinder → CallSiteFinder → Btf →
 * ConfigGen.offsetsFromBtf），把结果写进 _calib_equiv.txt，并与 9.455 内置条目逐项比对。
 * 只做只读计算，不碰 Android 运行时。
 */
class CalibEquivTest {

    private val img = File("C:/Users/Admin/Downloads/boot (3).img")

    @Test
    fun redmiBootCalibratesToTheBuiltinValues() {
        assumeTrue("boot img absent: " + img.path, img.exists())
        val out = StringBuilder()
        val header = FileInputStream(img).use { s -> val b = ByteArray(4096); var r = 0; while (r < b.size) { val n = s.read(b, r, b.size - r); if (n <= 0) break; r += n }; b.copyOf(r) }
        val info = BootImage.parseHeader(header)!!
        val image = BootImage.readKernel(FileInputStream(img), info)
        val kern = BootImage.inflateKernel(image)
        val k = kern.first
        val release = BootImage.kernelRelease(k) ?: "?"
        out.appendLine("release=" + release)
        out.appendLine("kernelBytes=" + k.size + " inflated=" + kern.second)

        val btfBytes = BootImage.extractBtf(k)
        check(btfBytes != null) { "no BTF" }
        val parsed = Btf.parse(btfBytes!!)
        val off = ConfigGen.offsetsFromBtf(parsed)
        out.appendLine("itimerSize=" + Integer.toHexString(off.itimerSize))
        out.appendLine("itimerNode=" + Integer.toHexString(off.itimerNode) + " itimerHead=" + Integer.toHexString(off.itimerHead) +
            " itimerElist=" + Integer.toHexString(off.itimerElist) + " itimerFiring=" + Integer.toHexString(off.itimerFiring) +
            " itimerHandling=" + Integer.toHexString(off.itimerHandling))
        out.appendLine("taskCred=" + Integer.toHexString(off.taskCred) + " taskComm=" + Integer.toHexString(off.taskComm))
        out.appendLine("credSize=" + Integer.toHexString(off.credSize) + " uid=" + Integer.toHexString(off.credUid) +
            " security=" + Integer.toHexString(off.credSecurity) + " user=" + Integer.toHexString(off.credUser) +
            " userNs=" + Integer.toHexString(off.credUserNs) + " ucounts=" + Integer.toHexString(off.credUcounts) +
            " groups=" + Integer.toHexString(off.credGroups))

        val ks = KallsymsFinder.find(k) { }
        check(ks != null) { "kallsyms not found" }
        out.appendLine("kallsyms=" + ks!!.symbols.size + " base=" + java.lang.Long.toHexString(ks.relativeBase))
        val names = listOf("do_timer_create", "selinux_state", "panic_on_warn", "root_user", "init_user_ns",
            "init_ucounts", "init_groups", "init_task", "init_cred")
        for (n in names) out.appendLine("sym " + n + "=" + java.lang.Long.toHexString(ks.symbols[n] ?: 0L))

        val site = CallSiteFinder.find(k, ks.symbols, ks.relativeBase)
        check(site != null) { "call sites not found" }
        site!!.detail.forEach { out.appendLine("site " + it) }
        out.appendLine("timerOffset=" + Integer.toHexString(site.timerOffset) +
            " credLow21=" + Integer.toHexString(site.credLow21) +
            " taskLow21=" + Integer.toHexString(site.taskLow21))
        val credAlloc = ConfigGen.credSlabObjectBytes(off.credSize)
        out.appendLine("credAlloc(rule 64-align)=" + Integer.toHexString(credAlloc) + " credReq=" + Integer.toHexString(off.credSize))
        File("D:/deepseek work/_calib_equiv.txt").writeText(out.toString(), Charsets.UTF_8)

        assertEquals(0x108, off.itimerSize)
        assertEquals(0x78, off.itimerNode)
        assertEquals(0x98, off.itimerHead)
        assertEquals(0xA8, off.itimerElist)
        assertEquals(0xB8, off.itimerFiring)
        assertEquals(0xC0, off.itimerHandling)
        assertEquals(0x820, off.taskCred)
        assertEquals(0x830, off.taskComm)
        assertEquals(0xB8, off.credSize)
        assertEquals(0xA8, site.timerOffset)
        assertEquals(0xE4064, site.credLow21)
        assertEquals(0xAB93C, site.taskLow21)
        assertEquals(java.lang.Long.parseUnsignedLong("FFFFFFC080195CA8", 16), ks.symbols["do_timer_create"])
        assertEquals(java.lang.Long.parseUnsignedLong("FFFFFFC082140748", 16), ks.symbols["init_cred"])
    }
}
