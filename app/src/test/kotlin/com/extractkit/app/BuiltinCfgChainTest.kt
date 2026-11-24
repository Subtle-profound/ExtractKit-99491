package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * 内置 profile（软件内的内置表）到 device.cfg 的端到端自检：
 * 六支链各自的内核族都必须在内置表里有档位，且档位能生成 payload 读得懂的 336+ B cfg。
 * 这里的字节偏移与 payload/src/runtime_cfg.h 的 load_device_cfg() 一一对应。
 */
class BuiltinCfgChainTest {

    private val families = listOf(
        "5.10." to false,   // honor 链，5.10 无 init_ucounts
        "5.15." to true,    // honor 链
        "6.1." to true,     // brm 链
        "6.6." to true,     // legacy 链
        "6.12." to true,    // legacy 链（pinned 9.104）
        "6.18." to true,    // k618 链
    )

    private fun pick(prefix: String): ConfigGen.Profile? =
        ConfigGen.PROFILES.firstOrNull { it.release.startsWith(prefix) }

    @Test
    fun everyChainFamilyHasBuiltinProfile() {
        for ((prefix, _) in families) {
            val p = pick(prefix)
            assertNotNull("内置表缺 $prefix 档位", p)
            // profileFor 也必须能按 release 精确命中同一档位（否则运行时取不到 cfg）
            val again = ConfigGen.profileFor(p!!.release)
            assertNotNull("profileFor 取不到 ${p.release}", again)
        }
    }

    @Test
    fun builtinProfileEmitsPayloadReadableCfg() {
        for ((prefix, needsUserNs) in families) {
            val p = pick(prefix)!!
            val blob = ConfigGen.emitCfgBlob(p.symbols, p.offsets, p.measured, p.schedAnchors)
            assertTrue("$prefix blob 太短 ${blob.size}", blob.size >= 12 + 38 * 8 + 5 * 4)
            assertEquals("$prefix magic", "EXKCFG01", String(blob, 0, 8, Charsets.US_ASCII))
            val bb = ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN)
            val count = bb.getInt(8)
            assertTrue("$prefix count=$count", count == 38 || count == 39)
            // 前 8 个 u64 = static_timer_site / low21 / selinux_state / panic_on_warn /
            // root_user / init_user_ns / init_ucounts / init_groups
            val f = LongArray(8) { bb.getLong(12 + it * 8) }
            assertTrue("$prefix 缺 do_timer_create 锚点（static_timer_site=0）", f[0] != 0L)
            assertEquals("$prefix low21 错", f[0] and 0x1FFFFFL, f[1])
            assertTrue("$prefix 缺 selinux_state", f[2] != 0L)
            if (needsUserNs) {
                assertTrue("$prefix 缺 root_user", f[4] != 0L)
                assertTrue("$prefix 缺 init_user_ns", f[5] != 0L)
            }
            // cred 锚点：task_cred / cred_uid 偏移必须非 0，否则链拿不到 cred
            assertTrue("$prefix off_task_cred=0", bb.getLong(12 + 8 * 8) != 0L)
            assertTrue("$prefix off_cred_uid=0", bb.getLong(12 + 23 * 8) != 0L)
        }
    }

    @Test
    fun k618BuiltinProfileMatchesReferenceTimerSite() {
        val p = pick("6.18.")!!
        val blob = ConfigGen.emitCfgBlob(p.symbols, p.offsets, p.measured, p.schedAnchors)
        val bb = ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN)
        val site = bb.getLong(12)
        val expect = (p.symbols["do_timer_create"] ?: 0L) + p.measured.timerSiteOffset
        assertEquals("k618 的 static_timer_site 应等于 do_timer_create+offset", expect, site)
        assertTrue("k618 static_timer_site 不是内核地址: " + java.lang.Long.toHexString(site),
            site.toULong() shr 40 == 0xFFFFFFuL)
    }

    @Test
    fun honorFamiliesGetSelinuxStateFromBuiltinTable() {
        for (prefix in listOf("5.10.", "5.15.")) {
            val p = pick(prefix)!!
            val se = p.symbols["selinux_state"] ?: 0L
            assertTrue("$prefix 内置表缺 selinux_state", se != 0L)
            val text = HonorMap.render(p.symbols, p.release)
            assertTrue("honor.map 没写进 selinux_state",
                text.contains("selinux_state 0x" + java.lang.Long.toHexString(se)))
            val known = HonorMap.NAMES.count { (p.symbols[it] ?: 0L) != 0L }
            assertTrue("honor.map nsyms 与内容不一致", text.contains("# nsyms=" + known))
        }
    }
}