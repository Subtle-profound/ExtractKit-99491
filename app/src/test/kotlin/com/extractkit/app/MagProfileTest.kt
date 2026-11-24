package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * 9.297：MAG-AN00 / 5.15.194 这条内置 profile 的回归断言。
 *
 * 用户提供的 boot_MAG-AN00_11.0.0.112.img（96 MiB 整分区 dump，
 * sha256 = 08f1ee997ed5a2480655cfb2a86b4dbbe519724a6eece61522c2c34c342a3046，
 * kernel=5.15.194-android13-8-gd1cdcc28f0f7，clang 14.0.7，无 -abogki 号）
 * 里的 task_struct / cred 偏移是反汇编核出来的，和 5.15.180 样板**不一样**
 * （taskCred 0x798 -> 0x750，taskComm 0x7A8 -> 0x760，credSize 0xA8 -> 0xB0）。
 * 这里把常量钉住，防止后续有人照样板又抄回去。
 */
class MagProfileTest {

    private val release = "5.15.194-android13-8-gd1cdcc28f0f7"
    private val bootSha = "08f1ee997ed5a2480655cfb2a86b4dbbe519724a6eece61522c2c34c342a3046"

    @Test
    fun magBootImageIsCoveredByBuiltinProfile() {
        val p = ConfigGen.profileFor(release)
        assertNotNull("MAG-AN00 / 5.15.194-android13-8 必须有内置 profile", p)
        assertEquals(bootSha, p!!.bootSha256)
        assertTrue("provenance 要写清 dump 形态", p.provenance.contains("ramdisk_size 0"))
        assertTrue("provenance 要写清楚不是 HONOR OTA 产线", p.provenance.contains("abogki"))
        assertTrue("机型限定 MAG-AN00", p.models.contains("MAG-AN00"))
    }

    @Test
    fun magOffsetsDifferFromTheOlderSample() {
        val p = ConfigGen.profileFor(release)!!
        // 反汇编：override_creds / revert_creds / commit_creds 全用 [task + 0x750]
        assertEquals("taskCred", 0x750L, p.offsets.taskCred.toLong())
        // 反汇编：__set_task_comm 用 [task + 0x760]，长度 0x10
        assertEquals("taskComm", 0x760L, p.offsets.taskComm.toLong())
        // 反汇编：put_cred_rcu 里 sub x19, x0, #0xa0 -> cred 结构体 0xB0
        assertEquals("credSize", 0xB0L, p.offsets.credSize.toLong())
        assertEquals("credUid", 0x4L, p.offsets.credUid.toLong())
        assertEquals("credSecurity", 0x78L, p.offsets.credSecurity.toLong())
    }

    @Test
    fun magCfgAnchorsMatchTheImage() {
        val p = ConfigGen.profileFor(release)!!
        val blob = ConfigGen.cfgBytesFor(p)
        assertNotNull("cfg 必须能生成（anchors 齐）", blob)
        val buf = ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals("EXKCFG01", String(blob!!, 0, 8, Charsets.US_ASCII))
        assertEquals(38, buf.getInt(8))
        buf.position(12)
        val u64 = LongArray(38) { buf.getLong() }
        // do_timer_create（本 Image 里 capstone 核对过的函数头）+ timerSiteOffset。
        // HONOR 链不读 device.cfg，这个 measured 只是为了通过 hasCfg 门禁，
        // 沿用 5.15.180 样板的 0xA4；真值仍以具体链条自己探到的为准。
        assertEquals(0xA4L, p.measured.timerSiteOffset.toLong())
        val staticTimer = 0xFFFFFFC0086EE384uL.toLong() + 0xA4L
        assertEquals(staticTimer, u64[0])
        assertEquals(staticTimer and 0x1FFFFF, u64[1])
        assertEquals(0xFFFFFFC00AE042A0uL.toLong(), u64[4])   // root_user
        assertEquals(0xFFFFFFC00B2D83E0uL.toLong(), u64[5])   // init_user_ns
        assertEquals(0xFFFFFFC00AE05AC0uL.toLong(), u64[6])   // init_ucounts
        assertEquals(0xFFFFFFC00AE05658uL.toLong(), u64[7])   // init_groups
        assertEquals(0x750L, u64[8])
        assertEquals(0x760L, u64[9])
        assertEquals(0xB0L, u64[13])
        assertEquals(0xC0L, u64[14])   // credAlloc（4k 页下一旦跨页就是 0xC0）
    }

    @Test
    fun honorMapCarriesEveryAnchorThisKernelNeeds() {
        // HONOR 链不读 device.cfg，符号表走 honor.map（loadmap=）。payload 真正查的
        // 只有 init_cred / selinux_state；5.15 支的 UAF 链还查 sig_enforce 与
        // modules_disabled，缺了会打 UAF-SYM-MISS 并回落编译期常量。
        assertEquals("honor.map 的符号名单", 4, HonorMap.NAMES.size)
        for (n in listOf("init_cred", "selinux_state", "sig_enforce", "modules_disabled")) {
            assertTrue("$n 必须在 honor.map 的符号名单里", HonorMap.NAMES.contains(n))
        }
    }

    @Test
    fun noOtherProfileSharesTheKey() {
        val key = ConfigGen.kernelKey(release)
        val same = ConfigGen.PROFILES.filter { ConfigGen.kernelKey(it.release) == key }
        assertEquals("同一个 kernelKey 只能有一条 profile，否则 cfg 会拿别人的地址写内核", 1, same.size)
        assertEquals(release, same[0].prefix)
    }
}
