package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * 9.296：内置 profile 的「出处」与 PTP-AN10 / 6.6.118 这条的回归断言。
 *
 * 用户提供的 boot.img（PTP-AN10，96 MiB 整分区 dump，
 * sha256 = 8e5773bd15e22991b36a5c01336be587ba26ce39934f6eb7fd0e8247aa6a940c）
 * 已经由内置 profile 覆盖，这里把「哪份固件、哪几个常量」钉成测试，防止后续
 * 有人手改常量却把出处对错、或者把 profile 匹配弄丢。
 */
class ProfileProvenanceTest {

    private val release = "6.6.118-android15-8-ga812a1946391-abogki576098434-4k"
    private val bootSha = "8e5773bd15e22991b36a5c01336be587ba26ce39934f6eb7fd0e8247aa6a940c"

    @Test
    fun ptpBootImageIsCoveredByBuiltinProfile() {
        val p = ConfigGen.profileFor(release)
        assertNotNull("PTP-AN10 / 6.6.118-android15-8 必须有内置 profile", p)
        // 9.296：出处跟着 profile 走（不再靠运行时 getprop 体检）
        assertEquals(bootSha, p!!.bootSha256)
        assertTrue("provenance 要写清 dump 形态", p.provenance.contains("ramdisk_size 0"))
        assertTrue(p.provenance.contains("init_ucounts"))
        assertTrue("机型限定 PTP-AN10", p.models.contains("PTP-AN10"))
    }

    @Test
    fun ptpCfgAnchorsMatchTheImage() {
        val p = ConfigGen.profileFor(release)!!
        val blob = ConfigGen.cfgBytesFor(p)
        assertNotNull("cfg 必须能生成（锚点齐）", blob)
        assertTrue("cfg 至少 336 B", blob!!.size >= 336)

        val buf = ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals("EXKCFG01", String(blob, 0, 8, Charsets.US_ASCII))
        assertEquals(38, buf.getInt(8))
        buf.position(12)
        val u64 = LongArray(38) { buf.getLong() }

        // do_timer_create 0xFFFFFFC0803B1340 + timerSiteOffset 0x94 —— 反汇编核对过的判空点
        val staticTimer = 0xFFFFFFC0803B1340uL.toLong() + 0x94L
        assertEquals(staticTimer, u64[0])
        assertEquals(staticTimer and 0x1FFFFF, u64[1])
        // cred 锚点：全部指向这份 Image 里的静态结构
        assertEquals(0xFFFFFFC08219F228uL.toLong(), u64[4])   // root_user
        assertEquals(0xFFFFFFC08219EF98uL.toLong(), u64[5])   // init_user_ns
        assertEquals(0xFFFFFFC0821A0CF8uL.toLong(), u64[6])   // init_ucounts
        assertEquals(0xFFFFFFC0821A0788uL.toLong(), u64[7])   // init_groups
        // 结构偏移：task_struct / cred 都是 6.6 arm64 4k 的值
        assertEquals(0x820L, u64[8])
        assertEquals(0x830L, u64[9])
        assertEquals(0xB8L, u64[13])
        assertEquals(0xB8L, u64[14])
    }

    @Test
    fun everyRecordedOriginIsAWellFormedSha256() {
        val recorded = ConfigGen.PROFILES.filter { it.bootSha256.isNotEmpty() }
        assertTrue("至少一条 profile 记了出处", recorded.isNotEmpty())
        for (p in recorded) {
            assertEquals("${p.name} 的 bootSha256 必须是 64 位小写 hex", 64, p.bootSha256.length)
            assertTrue(
                "${p.name} 的 bootSha256 含非 hex 字符：${p.bootSha256}",
                p.bootSha256.all { it in '0'..'9' || it in 'a'..'f' },
            )
            assertTrue("${p.name} 记了 sha 却没写 provenance", p.provenance.isNotEmpty())
        }
    }
}
