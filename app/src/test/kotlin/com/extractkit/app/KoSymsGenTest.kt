package com.extractkit.app

import org.junit.Test
import java.io.File

/**
 * 用上游那份 ko_syms 的 226 个符号名，配 gdf8d34 这颗 boot.img 自己的 kallsyms 地址，
 * 生成同格式的 ko-syms-<release>.txt（上游文件里的地址属于 g142ddad 那个 build，不能直接搬）。
 */
class KoSymsGenTest {

    private val upDir = File("D:/deepseek work/refdata/_up99491_clean/CVE-2026-99491-FANXIAOCHAO-main/data")
    private val upFile = File(upDir, "ko_syms_6.12.58-android16-6-g142ddad31e60-abogki576095858-4k.txt").let {
        if (it.isFile) it else File(upDir, "ko-syms-6.12.58-android16-6-g142ddad31e60-abogki576095858-4k.txt")
    }
    private val boot = File("C:/Users/Admin/Downloads/boot.img")

    @Test
    fun generate() {
        if (!boot.isFile) return
        val names = if (upFile.isFile) upFile.readLines()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .map { it.substringBeforeLast(' ') }
        else return
        val raw = boot.readBytes()
        val info = BootImage.parseHeader(raw.copyOfRange(0, 4096))!!
        val image = raw.copyOfRange(info.kernelOffset.toInt(), info.kernelOffset.toInt() + info.kernelSize)
        val release = BootImage.kernelRelease(image) ?: error("release")
        val found = KallsymsFinder.find(image) ?: error("kallsyms")
        val base = found.relativeBase
        val dbg = java.lang.StringBuilder("PROBE") 
        for (n in listOf("_text","_stext","stext","selinux_state","init_cred","input_dev_list")) dbg.append(" ").append(n).append("=").append(found.symbols[n]?.let { "0x" + java.lang.Long.toHexString(it) } ?: "-")
        dbg.append(" base=0x").append(java.lang.Long.toHexString(base)).append(" numSyms=").append(found.numSyms)
        File("D:/deepseek work/_calib401/probe.txt").writeText(dbg.toString() + "\n")
        val sb = StringBuilder()
        sb.append("# format: 1\n")
        sb.append("# kernel_release: ").append(release).append('\n')
        sb.append("# symbol_count: ").append(names.size).append('\n')
        sb.append("# note: link-time VAs; ko_patch adds the boot slide\n")
        val missing = StringBuilder()
        var n = 0
        for (name in names) {
            val off = found.symbols[name]
            if (off == null) { missing.append(name).append(' '); continue }
            val va = off // KallsymsFinder already returns absolute link-time VAs (probe: _text=0xffffffc080000000)
            sb.append(name).append(' ').append(java.lang.Long.toUnsignedString(va, 16)).append('\n')
            n++
        }
        val out = File("D:/deepseek work/_calib401")
        out.mkdirs()
        File(out, "ko-syms-" + release + ".txt").writeText(sb.toString())
        File(out, "syms-note.txt").writeText("release=" + release + " lines=" + n + " missing=" + missing.toString() +
            " base=0x" + java.lang.Long.toHexString(base) + "\n")
    }
}