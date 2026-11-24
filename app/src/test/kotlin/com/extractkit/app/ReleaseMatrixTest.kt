package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * release -> 分支 payload 的映射测试。
 *
 * 钉住三件事：
 *  1) 只认 主.次 两段，补丁号与构建串不参与（9.66 的坑：5.10.252-android12 被截成
 *     5.10.252，永远匹配不到 PER_FAMILY 的 5.10）；
 *  2) 不在六支内的一律 null（调用方回落字面版 payload，不猜）；
 *  3) describe() 的话术要能解释「为什么没命中」，别让人对着日志猜。
 */
class ReleaseMatrixTest {

    @Test
    fun android12FiveTenMatches() {
        val rel = "5.10.252-android12-9-g3f1c2b7d8e9f-ab12345678"
        assertEquals("5.10", ReleaseMatrix.majorMinor(rel))
        assertEquals("5.10", ReleaseMatrix.familyOf(rel))
    }

    @Test
    fun android15SixSixMatches() {
        // 真机 PPG-AN00 的形态
        val rel = "6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k"
        assertEquals("6.6", ReleaseMatrix.familyOf(rel))
    }

    @Test
    fun android17SixEighteenMatches() {
        assertEquals("6.18", ReleaseMatrix.familyOf("6.18.21-android17-5-g0123456789ab-ab00000000"))
    }

    @Test
    fun patchNumberDoesNotLeakIntoFamily() {
        // 关键：不能因为 release 里有 .252 就把 family 算成 5.10.252
        val fam = ReleaseMatrix.familyOf("5.10.252-android12-9-gffffffffffff-ab11111111")
        assertEquals("5.10", fam)
    }

    @Test
    fun unknownBranchFallsBackToNull() {
        assertNull(ReleaseMatrix.familyOf("6.7.1-android15-8-gdeadbeef-ab22222222"))
        assertNull(ReleaseMatrix.payloadOf("6.7.1-android15-8-gdeadbeef-ab22222222"))
    }

    @Test
    fun emptyOrNullReleaseIsNull() {
        assertNull(ReleaseMatrix.majorMinor(null))
        assertNull(ReleaseMatrix.majorMinor(""))
        assertNull(ReleaseMatrix.majorMinor("   "))
        assertNull(ReleaseMatrix.familyOf(null))
    }

    @Test
    fun knownBranchHasPayload() {
        // 9.281：回到 9.213 的按分支拆份形态，六支都要能选到自己的字节。
        for ((fam, rel) in listOf(
            "5.10" to "5.10.252-android12",
            "5.15" to "5.15.180-android13",
            "6.1" to "6.1.157-android14",
            "6.6" to "6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k",
            "6.12" to "6.12.58-android16",
            "6.18" to "6.18.21-android17-5-g0123456789ab-ab00000000",
        )) {
            val p = ReleaseMatrix.payloadOf(rel)
            assertNotNull("$fam 没有选到 payload", p)
            assertEquals("ek-core-uid0-$fam", p!!.name)
            assertEquals(Payloads.PER_FAMILY[fam]!!.sha256, p.sha256)
        }
        assertNull(ReleaseMatrix.payloadOf("6.7.1-android15-8-gdeadbeef-ab22222222"))
        assertEquals("ek-core-uid0", Payloads.UID0.name)
    }


    @Test
    fun noFamilyIsHeldAnyMore() {
        // 9.185：6.12 已从 build_fam.py 的 PINNED_9104 移出、用当前主源重编，
        // 不再是「会 panic 的冻结字节」，所以一支都不该被 held。
        assertFalse(ReleaseMatrix.isHeld(ReleaseMatrix.familyOf("6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k")))
        assertFalse(ReleaseMatrix.isHeld(ReleaseMatrix.familyOf("6.6.118-android15-8-g554929766a0d-abogki544555896-4k")))
        assertFalse(ReleaseMatrix.isHeld(null))
        assertTrue(ReleaseMatrix.HOLD.isEmpty())
        assertFalse(ReleaseMatrix.describe("6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k").contains("frozen"))
    }

    @Test
    fun describeExplainsMiss() {
        val hit = ReleaseMatrix.describe("6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k")
        assertEquals(true, hit.contains("6.6"))
        assertEquals(true, hit.contains("-> family"))
        val miss = ReleaseMatrix.describe("6.7.1-android15-8-gdeadbeef")
        assertEquals(true, miss.contains("outside family matrix"))
        val bad = ReleaseMatrix.describe(null)
        assertEquals(true, bad.contains("cannot parse major.minor"))
    }
}
