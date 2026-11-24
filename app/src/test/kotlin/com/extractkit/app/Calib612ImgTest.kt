package com.extractkit.app

import org.junit.Test
import java.io.File

/** 一次性：用户给的 C:/Users/Admin/Downloads/boot.img 全量重标，产物落 refdata/calib/。 */
class Calib612ImgTest {

    @Test
    fun build() {
        val f = File("C:/Users/Admin/Downloads/boot.img")
        if (!f.isFile) { println("[p] missing " + f.path); return }
        val raw = f.readBytes()
        val info = BootImage.parseHeader(raw.copyOfRange(0, 4096))
        if (info == null) { println("[p] header null"); return }
        println("[p] kernel off=" + info.kernelOffset + " size=" + info.kernelSize)
        val image = raw.copyOfRange(info.kernelOffset.toInt(), info.kernelOffset.toInt() + info.kernelSize)
        val release = BootImage.kernelRelease(image)
        println("[p] release=" + release)
        if (release == null) return
        val btf = runCatching { BootImage.extractBtf(image)?.let { Btf.parse(it) } }.getOrNull()
        println("[p] btf=" + (btf != null))
        val found = KallsymsFinder.find(image)
        if (found == null) { println("[p] no kallsyms"); return }
        println("[p] base=0x" + java.lang.Long.toHexString(found.relativeBase) + " syms=" + found.symbols.size)
        val template = File("src/main/assets/payload/wacom/profile-6.6.json").readText()
        val built = WacomCalib.build(template, release, 4096, image, found.relativeBase, found.symbols, btf)
        println("[p] derived=" + built.derived + " problems=" + built.problems.size + " notes=" + built.notes.size)
        built.problems.forEach { println("[!] " + it) }
        built.notes.forEach { println("[.] " + it) }
        val out = File("D:/deepseek work/refdata/calib/" + release + ".json")
        out.parentFile.mkdirs()
        out.writeText(built.json)
        println("[p] wrote " + out.length() + " -> " + out.path)
    }
}
