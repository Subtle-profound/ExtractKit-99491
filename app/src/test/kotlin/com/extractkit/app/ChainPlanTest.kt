package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 9.146 的链选择：一个族一条实现，选错链比跑失败更糟（会对着别人的布局写内核页）。
 * 这里钉住三件事：
 *  1) 族 → 链的映射，尤其是 5.10 与 5.15 必须同链、6.6 与 6.12 必须留在 legacy；
 *  2) 矩阵外的内核一律回落 legacy（字面版），不得猜一条新链；
 *  3) 9.269 起六支 payload 各自独立源、同一参数面，argsFor 不再加工命令行。
 */
class ChainPlanTest {

    @Test
    fun familyToChain() {
        assertEquals(Chain.HONOR, ChainPlan.of("5.10"))
        assertEquals(Chain.HONOR, ChainPlan.of("5.15"))
        assertEquals(Chain.BRM, ChainPlan.of("6.1"))
        assertEquals(Chain.LEGACY, ChainPlan.of("6.6"))
        assertEquals(Chain.LEGACY, ChainPlan.of("6.12"))
        assertEquals(Chain.K618, ChainPlan.of("6.18"))
    }

    @Test
    fun outsideMatrixFallsBackToLegacy() {
        assertEquals(Chain.LEGACY, ChainPlan.of("6.7"))
        assertEquals(Chain.LEGACY, ChainPlan.of(null))
        assertEquals(Chain.LEGACY, ChainPlan.ofRelease(null))
        assertEquals(Chain.LEGACY, ChainPlan.ofRelease(""))
    }

    @Test
    fun releaseToChain() {
        assertEquals(Chain.HONOR, ChainPlan.ofRelease("5.10.236-android12-9-g4b262e5255ed"))
        assertEquals(Chain.BRM, ChainPlan.ofRelease("6.1.157-android14-11-g7d3922fade43"))
        assertEquals(Chain.K618, ChainPlan.ofRelease("6.18.21-android17-5-g928d1bb4f1d7"))
        assertEquals(Chain.LEGACY, ChainPlan.ofRelease("6.6.118-android15-8-g554929766a0d"))
    }

    @Test
    fun chainNamesAreDistinct() {
        val names = Chain.entries.map { it.chainName }.toSet()
        assertEquals(Chain.entries.size, names.size)
        assertTrue(names.contains("legacy-EK-CORE"))
        assertNotEquals("", ChainPlan.nameOf("6.1.157-android14"))
    }


    @Test
    fun argsForKeepsModeArgsForEveryFamily() {
        assertEquals("check", ChainPlan.argsFor("5.10", "check", "/data/local/tmp/x"))
        assertEquals("check", ChainPlan.argsFor("6.1", "check", "/data/local/tmp/x"))
        assertEquals("check", ChainPlan.argsFor("6.6", "check", "/data/local/tmp/x"))
        assertEquals("check", ChainPlan.argsFor("6.18", "check", "/data/local/tmp/x"))
    }


    @Test
    fun honorMapIsGeneratedNotBundled() {
        val text = HonorMap.render(
            mapOf("init_cred" to 0xffffffc00a830c18UL.toLong(), "selinux_state" to 0xffffffc00ae84b38UL.toLong()),
            "6.6.118-android15",
        )
        val lines = text.trim().lines()
        assertEquals("# extractkit-map v1", lines[0])
        assertEquals("# kernel=6.6.118-android15", lines[1])
        assertEquals("# nsyms=2", lines[2])
        assertTrue(lines.contains("init_cred 0xffffffc00a830c18"))
        assertTrue(lines.contains("selinux_state 0xffffffc00ae84b38"))
        // 9.180 起表里只有链真正会查的两个名字
        assertEquals(4, HonorMap.NAMES.size)
        assertEquals(HonorMap.NAMES.size + 3, lines.size)
    }

    @Test
    fun brmSettleThresholdIs120s() {
        assertEquals(120, ChainPlan.BRM_MIN_UPTIME_SEC)
    }
}
