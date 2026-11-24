package com.extractkit.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 9.292：收尾 late-load 的 root-cmd 引导。
 *
 * 背景（反汇编 + 真机日志）：原字节 payload 跑完不留 su 客户端，只留一个 unix socket；
 * 但它的 root 子进程认 env `PPG_ROOT_CMD`，非空就 execl("/system/bin/sh","sh","-c",cmd)。
 * 所以我们的做法是**再跑一次同样的字节**（零 argv、不改任何字节），只借这次 uid=0。
 */
class LateLoadRootCmdTest {

    private fun cmd(mgrUid: Int? = 10280): String = ExtractEngine.rootCmdRunCmd(
        script = "/data/local/tmp/extract-kit/ksu_stage.sh",
        mgr = "io.milksu.manager",
        mgrUid = mgrUid,
        workDir = "/data/local/tmp/extract-kit",
    )

    @Test
    fun theEnvIsSetBeforeTheSameZeroArgPayloadCall() {
        val c = cmd()
        assertTrue("PPG_ROOT_CMD 不在载荷调用之前", c.indexOf("PPG_ROOT_CMD=") < c.indexOf("./glpreload"))
        assertTrue("主调用形态被改了", c.startsWith("cd /data/local/tmp && PPG_ROOT_CMD="))
        // 载荷仍然零参数：./glpreload 后面紧跟重定向，没有任何 argv
        assertTrue("给载荷加了参数", c.contains("./glpreload > "))
    }

    @Test
    fun theRootChildRunsOurStage() {
        val c = cmd()
        assertTrue(c.contains("/system/bin/sh /data/local/tmp/extract-kit/ksu_stage.sh"))
        assertTrue(c.contains("> /data/local/tmp/ksu_stage.out 2>&1"))
        assertTrue("没走 register-only", c.contains("EXTRACTKIT_REGISTER_ONLY=1"))
    }

    @Test
    fun managerUidIsOptional() {
        assertTrue(cmd(10280).contains("EXTRACTKIT_MGR_UID=10280"))
        assertFalse(cmd(null).contains("EXTRACTKIT_MGR_UID"))
    }

    @Test
    fun neverTouchesDataAdb() {
        assertFalse("root-cmd 碰了 /data/adb", cmd().contains("/data/adb"))
    }

    @Test
    fun singleQuotesAreEscaped() {
        assertTrue(ExtractEngine.quoteArg("a'b").startsWith("'a"))
        assertTrue(ExtractEngine.quoteArg("a'b").endsWith("'"))
        assertTrue(ExtractEngine.quoteArg("a'b").contains("'\\''"))
    }
}
