package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * 9.353：标定器（WacomCalib）必须把一颗真实内核解析成 payload 直接能吃的 profile。
 * 输入用 g554929766a0d 的裸 kernel 镜像：BTF 给结构体偏移，kallsyms 给符号地址，
 * 镜像里的 cap_last_cap 变量给 cap 位图，prepare_creds 的 BL 给 cred 站点低 21 位。
 */
class WacomCalibTest {
    private val k = "6.6.118-android15-8-g554929766a0d-abogki544555896-4k"
    private val imgPath = "D:/deepseek work/refdata/boot_new_unknown.kernel"

    private class Real(
        val image: ByteArray,
        val syms: Map<String, Long>,
        val base: Long,
        val btf: Btf,
    )

    private fun template(): String {
        val f = File("src/main/assets/payload/wacom/profile-6.6.json")
        assertTrue("模板不见了: " + f.absolutePath, f.isFile)
        return f.readText()
    }

    private fun real(): Real? {
        val f = File(imgPath)
        if (!f.isFile) return null
        val image = f.readBytes()
        val found = KallsymsFinder.find(image) { _ -> } ?: return null
        val blob = BootImage.extractBtf(image) ?: return null
        return Real(image, found.symbols, found.relativeBase, Btf.parse(blob))
    }

    private fun build(r: Real?, release: String = k, override: Int = 0): WacomCalib.Built {
        requireNotNull(r)
        return WacomCalib.build(
            template = template(),
            release = release,
            pageSize = 4096,
            image = r.image,
            relativeBase = r.base,
            symbols = r.syms,
            btf = r.btf,
            credSiteOverride = override,
        )
    }

    @Test
    fun derivesEveryKeyThePayloadNeeds() {
        val r = real()
        assumeTrue("没有 " + imgPath + "，跳过真镜像用例", r != null)
        val b = build(r)
        assertEquals("problems: " + b.problems.joinToString(" | "), 0, b.problems.size)
        val json = b.json
        // 符号地址来自 kallsyms，必须原样写进去（大写/无前缀都不行）
        assertTrue(json.contains("0xffffffc080eaf028"))
        assertTrue(json.contains("0xffffffc08214a140"))
        // cap 位图来自镜像里的 cap_last_cap 变量
        assertTrue(json.contains("2199023255551"))
        // cred 站点由 prepare_creds 的 BL 推出，实测 0x38458
        assertTrue(json.contains("230488"))
        assertTrue(json.contains(k))
        assertTrue("derived=" + b.derived, b.derived > 40)
    }

    @Test
    fun overrideWinsOverDisassembly() {
        val r = real()
        assumeTrue("没有 " + imgPath + "，跳过真镜像用例", r != null)
        val b = build(r, override = 123456)
        assertTrue(b.json.contains("123456"))
    }

    @Test
    fun validatorRejectsAWrongCapMask() {
        val r = real()
        assumeTrue("没有 " + imgPath + "，跳过真镜像用例", r != null)
        val bad = build(r).json.replace("2199023255551", "1")
        assertTrue(WacomCalib.validate(bad).any { it.contains("cap_full_mask") })
    }

    @Test
    fun validatorRejectsAMissingSymbol() {
        val r = real()
        assumeTrue("没有 " + imgPath + "，跳过真镜像用例", r != null)
        val bad = build(r).json.replace("0xffffffc0822bf820", "0x0")
        assertTrue(WacomCalib.validate(bad).any { it.contains("sym_input_dev_list") })
    }

    @Test
    fun emptyReleaseIsRejected() {
        val b = WacomCalib.build(template(), "?", 4096, ByteArray(0), 0L, emptyMap(), null)
        assertTrue(!b.ok)
        assertTrue(b.problems.any { it.contains("release") })
    }
}
