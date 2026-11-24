package com.extractkit.app

import org.junit.Test
import java.io.File

/**
 * 9.405 离线探针：把用户手上这批 boot 跑一遍 —— 压缩内核能不能解开、6.1 的
 * profile + ko-syms 能不能生成。没有文件就跳过，不参与断言。
 */
class BootProbe405Test {

    private val images = listOf(
        "C:/Users/Admin/Downloads/boot.img",
        "C:/Users/Admin/Downloads/boot (1).img",
        "D:/fw135/boot.img",
        "D:/PPGWork/cache/amg_ota/boot.img",
        "E:/123pan/Downloads/boot.img",
        "E:/123pan/Downloads/6.1.128/boot.img",
        "F:/MTN-AN80-firmware/img/boot.img",
        "C:/Users/Admin/Downloads/boot_MAG-AN00_11.0.0.112.img",
    )

    @Test
    fun probeAll() {
        val out = File("D:/deepseek work/_calib405")
        out.mkdirs()
        val sb = StringBuilder()
        for (path in images) {
            val f = File(path)
            if (!f.isFile) { sb.append(path).append(": missing\n"); continue }
            val raw = f.readBytes()
            val info = runCatching { BootImage.parseHeader(raw.copyOfRange(0, 4096)) }.getOrNull()
            if (info == null) { sb.append(path).append(": bad header\n"); continue }
            val off = info.kernelOffset.toInt()
            val seg = raw.copyOfRange(off, minOf(off + info.kernelSize, raw.size))
            val (kern, how) = BootImage.inflateKernel(seg)
            val release = BootImage.kernelRelease(kern) ?: "?"
            sb.append(path).append("\n  segment=").append(seg.size)
                .append(" inflate=").append(how ?: "none")
                .append(" -> ").append(kern.size)
                .append("\n  release=").append(release).append('\n')
            if (release == "?") { continue }
            val fam = ReleaseMatrix.familyOf(release)
            val btf = runCatching { BootImage.extractBtf(kern)?.let { Btf.parse(it) } }.getOrNull()
            val found = runCatching { KallsymsFinder.find(kern) }.getOrNull()
            val template = File("src/main/assets/payload/wacom/profile-6.6.json").readText()
            val built = runCatching {
                WacomCalib.build(template, release, 4096, kern, found?.relativeBase ?: 0L, found?.symbols ?: emptyMap(), btf)
            }.getOrNull()
            if (built == null) { sb.append("  profile: FAILED").append('\n'); continue }
            File(out, release + ".json").writeText(built.json)
            sb.append("  family=").append(fam)
                .append(" btf=").append(if (btf == null) "none" else "ok")
                .append(" syms=").append(found?.symbols?.size ?: 0)
                .append(" derived=").append(built.derived)
                .append(" problems=").append(built.problems.size).append('\n')
            built.problems.forEach { sb.append("  ! ").append(it).append('\n') }
            sb.append("  validate=").append(WacomCalib.validate(built.json).joinToString(" | ")).append('\n')
            // ko-syms 表：名字模板按家族挑，地址用本机 kallsyms
            val tpl = File("src/main/assets/" + WacomSyms.templateAsset(fam)).readText()
            val table = WacomSyms.build(tpl, release, found?.symbols ?: emptyMap())
            File(out, "ko-syms-" + release + ".txt").writeText(table.text)
            sb.append("  ko-syms: ").append(table.symbols).append(" symbols, missing=")
                .append(table.missing.size).append('\n')
            table.missing.take(5).forEach { sb.append("    - ").append(it).append('\n') }
        }
        File(out, "summary.txt").writeText(sb.toString())
    }
}
