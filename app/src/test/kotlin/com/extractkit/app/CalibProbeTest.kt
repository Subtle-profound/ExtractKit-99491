package com.extractkit.app

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * 9.354：把用户给的四份 boot.img 各自跑一遍标定链，结果写到 refdata/calib/。
 * 只做离线推导，不进 assets，也不碰真机。
 */
class CalibProbeTest {

    private val inputs = listOf(
        "D:/fw135/boot.img.kernel",
        "E:/123pan/Downloads/6.1.128/boot.img.kernel",
        "E:/123pan/Downloads/boot.img.kernel",
        "F:/MTN-AN80-firmware/img/boot.img.kernel",
    )

    @Test
    fun calibratesEveryProvidedImage() {
        val template = File("src/main/assets/payload/wacom/profile-6.6.json").readText()
        val outDir = File("D:/deepseek work/refdata/calib")
        outDir.mkdirs()
        val summary = StringBuilder()
        for (p in inputs) {
            val f = File(p)
            if (!f.isFile) { summary.append("MISSING ").append(p).append('\n'); continue }
            val image = f.readBytes()
            val release = BootImage.kernelRelease(image) ?: "?"
            val btf = runCatching { BootImage.extractBtf(image)?.let { Btf.parse(it) } }.getOrNull()
            val found = KallsymsFinder.find(image)
            summary.append("== ").append(release).append('\n')
            if (found == null) { summary.append("   no kallsyms\n"); continue }
            summary.append("   base=0x").append(java.lang.Long.toHexString(found.relativeBase))
                .append(" syms=").append(found.symbols.size).append('\n')
            val built = WacomCalib.build(template, release, 4096, image, found.relativeBase, found.symbols, btf)
            summary.append("   derived=").append(built.derived).append(" problems=").append(built.problems.size).append('\n')
            built.problems.forEach { summary.append("   ! ").append(it).append('\n') }
            built.notes.forEach { summary.append("   . ").append(it).append('\n') }
            File(outDir, release + ".json").writeText(built.json)
        }
        File(outDir, "summary.txt").writeText(summary.toString())
        assertTrue("no image produced a profile", outDir.listFiles()!!.size > 1)
    }
}
