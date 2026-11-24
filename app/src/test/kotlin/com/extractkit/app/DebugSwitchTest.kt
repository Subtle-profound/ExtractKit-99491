package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/**
 * 9.192：use_fam / use_literal 两个调试开关带版本戳，过期自动清理。
 *
 * 钉住三件事：
 *  1) 开关不存在 → 不生效、不打日志（默认路径完全不受影响）；
 *  2) 版本戳等于当前 VERSION_NAME → 生效；
 *  3) 空白或旧版本号 → 不生效 + 文件被删掉 + 打一句说明。
 * 第 3 条是这次事故的根：纯 exists() 判定下，设备上残留一个空的 use_literal，
 * 会让之后每次升级都回落到字面版 payload。
 */
class DebugSwitchTest {

    private fun tmp(name: String): File =
        Files.createTempDirectory("sw").toFile().resolve(name).also { it.deleteOnExit() }

    @Test
    fun missingSwitchIsOffAndSilent() {
        val f = tmp("use_literal")
        val sw = debugSwitch(f.absolutePath)
        assertFalse(sw.on)
        assertNull(sw.note)
    }

    @Test
    fun stampedWithCurrentVersionIsOn() {
        val f = tmp("use_fam")
        f.writeText(BuildConfig.VERSION_NAME + "\n")
        val sw = debugSwitch(f.absolutePath)
        assertTrue(sw.on)
        assertNotNull(sw.note)
        assertTrue("开关该保留", f.exists())
    }

    @Test
    fun blankStampIsStaleAndDeleted() {
        val f = tmp("use_literal")
        f.writeText("")
        val sw = debugSwitch(f.absolutePath)
        assertFalse(sw.on)
        assertTrue(sw.note!!.contains("stale"))
        assertFalse("空白版本戳必须被删掉", f.exists())
    }

    @Test
    fun oldVersionStampIsStaleAndDeleted() {
        val f = tmp("use_literal")
        f.writeText("9.104\n")
        val sw = debugSwitch(f.absolutePath)
        assertFalse(sw.on)
        assertEquals(false, sw.on)
        assertTrue(sw.note!!.contains("9.104"))
        assertFalse(f.exists())
    }
}