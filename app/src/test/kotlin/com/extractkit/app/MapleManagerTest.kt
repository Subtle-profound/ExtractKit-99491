package com.extractkit.app

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * MapleSU（dev.maplesu.manager）接管的回归测试。
 *
 * 由来（9.193，用户 m09750）：在 ExtractKit 里选 MapleSU 当管理器跑 6.6.118 提权「无效」。
 * 两个独立原因：
 *  1) ksu_stage.sh 的 ksud_like() 只认 --version 首行里有 ksud 的二进制，而 MapleSU 的
 *     ksud 是 Rust 版，首行打「KernelSU version: 32680-5」，一个 ksud 字都没有 →
 *     唯一候选被拒，日志停在「[ksu] ksud 找不到可用来源」。
 *  2) 6.6 那支 payload 当时钉在 9.188 字节上，没有 real_cred 双写，而 6.6.118 的
 *     Uid 判据读的是 task->real_cred → 就算交接成功也读不到 uid=0。
 * 这里把「两个管理器表都认识 MapleSU」和「ksud_like 认 KernelSU 首行」钉住。
 */
class MapleManagerTest {

    private fun assetsRoot(): File =
        listOf("src/main/assets", "app/src/main/assets")
            .map { File(it) }
            .firstOrNull { it.isDirectory }
            ?: error("找不到 assets 目录（cwd=${File(".").absolutePath}）")

    private fun repoFile(rel: String): File =
        listOf(rel, "app/$rel", "../$rel").map { File(it) }.firstOrNull { it.isFile }
            ?: error("找不到 $rel（cwd=${File(".").absolutePath}）")

    @Test
    fun glassManagerTableKnowsMapleSu() {
        assertEquals("MapleSU", GLASS_MANAGERS["dev.maplesu.manager"])
    }

    @Test
    fun bothManagerTablesListMapleSu() {
        // GlassMainActivity.kt 里的 MANAGERS 是文件私有，只能按源码文本守
        for (f in listOf("src/main/kotlin/com/extractkit/app/GlassMainActivity.kt",
                         "src/main/kotlin/com/extractkit/app/GlassSheets.kt")) {
            val txt = repoFile(f).readText()
            assertTrue("$f 里没有 dev.maplesu.manager", txt.contains("\"dev.maplesu.manager\""))
        }
    }

    @Test
    fun ksudLikeAcceptsKernelSuVersionLine() {
        val sh = File(assetsRoot(), "stage/ksu_stage.sh").readText()
        // 上游原文的探测方式：跑一次 --version，第一行里出现 ksud 即认为是 ksud 二进制。
        assertTrue("没有 --version 探测", sh.contains("--version"))
        // 9.281 起首行判据同时认 ksud 与 kernelsu（MapleSU 的 Rust 版 ksud
        // 首行打 "KernelSU version: ..."，一个 ksud 字都没有）。
        assertTrue("首行判据不认 kernelsu", sh.contains("ksud|kernelsu"))
        // 管理器包名由 App 用 EXTRACTKIT_MGR 注入，脚本不再内置包名表。
        assertTrue("没有 EXTRACTKIT_MGR 注入点", sh.contains("EXTRACTKIT_MGR"))
        // 目标串取自 MapleSU libksud_ksu.so 的 "KernelSU version: {}"
        val line = "KernelSU version: 3.1.1 (32680-5)"
        assertTrue(line.lowercase().contains("kernelsu"))
    }
}
