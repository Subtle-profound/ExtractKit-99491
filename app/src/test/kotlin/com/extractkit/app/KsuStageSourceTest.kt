package com.extractkit.app

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 交接脚本（9.280：从零开始，直接采用上游参考实现的原文，不再叠加本地改动）。
 *
 * 该脚本的职责：定位管理器自带的 lib/arm64/ksud、探测 --package-name 支持、
 * 用它 late-load kernelsu，并以 /proc/modules 里真的出现 kernelsu 作为成功判据。
 * 这里钉住的都是脚本里真实存在的命令级片段。
 */
class KsuStageSourceTest {

    private fun script(): String =
        listOf("src/main/assets/stage/ksu_stage.sh", "app/src/main/assets/stage/ksu_stage.sh")
            .map { File(it) }
            .firstOrNull { it.isFile }
            ?.readText()
            ?: error("找不到 assets/stage/ksu_stage.sh（cwd=${File(".").absolutePath}）")

    @Test
    fun scansManagerLibArm64ForKsud() {
        val sh = script()
        assertTrue("没有按 lib/arm64 扫管理器的 ksud", sh.contains("/lib/arm64"))
        assertTrue("没有 ksud_like 探测", sh.contains("ksud_like()"))
        assertTrue("没有 --version 探测", sh.contains("--version"))
    }

    @Test
    fun takesManagerFromEnvAndNeverBorrowsAcrossPackages() {
        val sh = script()
        // 9.281 起不再有写死的 KNOWN 包名表：管理器包名由 App 注入，
        // 写死会出现「选了 MilkSU 却注册成 SukiSU」。
        assertTrue("没有 EXTRACTKIT_MGR 注入点", sh.contains("EXTRACTKIT_MGR"))
        assertTrue("没有 9.204 不跨包政策文案", sh.contains("9.204 policy"))
        // 只在选中包自己的 lib/arm64 里找 ksud
        assertTrue("没有按 lib/arm64 扫管理器", sh.contains("/lib/arm64"))
    }

    @Test
    fun successRequiresKernelsuInProcModules() {
        val sh = script()
        // 光看 rc=0 不算成功：必须真的在 /proc/modules 里看到 kernelsu。
        assertTrue("没有 /proc/modules 判据", sh.contains("grep -q '^kernelsu ' /proc/modules"))
        assertTrue("没有 KSU_LOADED 输出", sh.contains("KSU_LOADED"))
        assertTrue("没有 KSU_MISSING 输出", sh.contains("KSU_MISSING"))
    }

    @Test
    fun neverWritesOutsideAdbKsuPaths() {
        val sh = script()
        // 脚本只会动 /data/adb 下的 ksud 与 ksu/bin；不许碰模块目录以外的系统路径。
        assertFalse("脚本在写 /system", sh.contains("> /system"))
        assertFalse("脚本在写 /vendor", sh.contains("> /vendor"))
    }

    @Test
    fun probeOnlyNeverRegisters() {
        val sh = script()
        // 9.291：探针模式只发现 + 自检，绝不注册、绝不碰 /data/adb。
        assertTrue("没有 PROBE_ONLY 环境开关", sh.contains("EXTRACTKIT_PROBE_ONLY"))
        assertTrue("没有 probe-only 出口", sh.contains("probe-only: nothing registered; /data/adb untouched"))
    }

    @Test
    fun appidIsCheckedAgainstTheChosenManager() {
        val sh = script()
        // 判据不能是 rc=0：payload 写死的是 KernelSU，必须比对箭头右侧是不是所选包名。
        assertTrue("没有 appid 严格比对", sh.contains("is not \$MGR"))
        assertTrue("没有 register 失败退出码", sh.contains("exit=4"))
        assertTrue("没有 appid 未验证退出码", sh.contains("leave 6"))
        // 9.317：所有提前退出现在都走 leave()，它先把 SELinux 恢复成 Enforcing。
        assertTrue("没有统一退出助手", sh.contains("leave() {"))
        assertTrue("提前退出没恢复 SELinux", sh.contains("selinux restored: enforce="))
    }

    @Test
    fun candidatesAreRanked() {
        val sh = script()
        assertTrue("没有候选排名行", sh.contains("[resolve] cand "))
        assertTrue("没有候选落盘", sh.contains("candidates.all"))
        assertTrue("没有 CLI 自检", sh.contains("[resolve] cli_ok="))
    }

    @Test
    fun rootChildLeavesUidZeroEvidence() {
        val sh = script()
        // 9.292：payload 的 root 子进程（PPG_ROOT_CMD 执行口）跑这个脚本时自报身份，
        // 并把 uid=0 证据与内核参数回读落盘给 shell 域的 App 读。
        assertTrue("没有 invoked-as 自报身份", sh.contains("[ksu] invoked-as uid="))
        assertTrue("没有 root_uid 证据文件", sh.contains("root_uid"))
        assertTrue("没有内核参数回读文件", sh.contains("ksu_params"))
        assertTrue("late-load 调用没有超时上限", sh.contains("RUNTO"))
    }

    @Test
    fun crossPackageFallbackIsGone() {
        val sh = script()
        // 9.319（用户指令）：late load 只认所选管理器包，跨包兜底开关与 /data/adb 来源全部删除。
        assertFalse("还留着跨包兜底开关", sh.contains("EXTRACTKIT_KSUD_FALLBACK"))
        assertFalse("还在 /data/adb/ksu/lib 捡模块", sh.contains("ls /data/adb/ksu/lib"))
        assertTrue("没有拒收包外 hint 的行", sh.contains("hint rejected (outside package)"))
        assertTrue("没有包内 ko 选择器", sh.contains("static_pick_ko"))
        assertTrue("没有 ko-only 快路径", sh.contains("[ksu] package ships a module:"))
    }
}
