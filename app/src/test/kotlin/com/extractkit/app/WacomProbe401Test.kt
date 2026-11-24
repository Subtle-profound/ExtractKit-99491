package com.extractkit.app

import org.junit.Test
import java.io.File

/** 离线探针：用户给的 6.12.58 gdf8d34 boot.img 能否生成 99491 profile。 */
class WacomProbe401Test {

    @Test
    fun buildProfile() {
        val f = File("C:/Users/Admin/Downloads/boot.img")
        if (!f.isFile) return
        val raw = f.readBytes()
        val info = BootImage.parseHeader(raw.copyOfRange(0, 4096))!!
        val image = raw.copyOfRange(info.kernelOffset.toInt(), info.kernelOffset.toInt() + info.kernelSize)
        val release = BootImage.kernelRelease(image) ?: "?"
        val btf = runCatching { BootImage.extractBtf(image)?.let { Btf.parse(it) } }.getOrNull()
        val found = KallsymsFinder.find(image)!!
        val template = File("src/main/assets/payload/wacom/profile-6.6.json").readText()
        val built = WacomCalib.build(template, release, 4096, image, found.relativeBase, found.symbols, btf)
        val out = File("D:/deepseek work/_calib401")
        out.mkdirs()
        File(out, release + ".json").writeText(built.json)
        val sb = StringBuilder()
        sb.append("release=").append(release).append('\n')
        sb.append("btf=").append(if (btf == null) "none" else "ok").append('\n')
        sb.append("derived=").append(built.derived).append(" problems=").append(built.problems.size).append('\n')
        built.problems.forEach { sb.append("! ").append(it).append('\n') }
        built.notes.forEach { sb.append(". ").append(it).append('\n') }
        sb.append("validate=").append(WacomCalib.validate(built.json).joinToString(" | ")).append('\n')
        sb.append("bytes=").append(built.json.toByteArray().size).append('\n')
        File(out, "summary.txt").writeText(sb.toString())
    }
}