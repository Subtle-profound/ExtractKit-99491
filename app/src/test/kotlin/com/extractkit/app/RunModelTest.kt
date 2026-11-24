package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RunModelTest {

    @Test
    fun absentShizukuShowsInstall() {
        val b = bannerFor(ShellState.ABSENT, rooted = false, busy = false, stage = "", lastFail = null)
        assertEquals("环境受限", b.title)
        assertEquals(BannerAction.INSTALL_SHIZUKU, b.action)
    }

    @Test
    fun noPermissionAsksForGrant() {
        val b = bannerFor(ShellState.NO_PERM, rooted = false, busy = false, stage = "", lastFail = null)
        assertEquals("需要授权", b.title)
        assertEquals(BannerAction.REQUEST_PERM, b.action)
    }

    @Test
    fun grantedAndIdleIsReady() {
        val b = bannerFor(ShellState.CONNECTED, rooted = false, busy = false, stage = "", lastFail = null)
        assertEquals("就绪", b.title)
        assertEquals(BannerAction.NONE, b.action)
    }

    @Test
    fun busyShowsStage() {
        val b = bannerFor(ShellState.CONNECTED, rooted = false, busy = true, stage = "预检环境", lastFail = null)
        assertEquals("执行中", b.title)
        assertEquals("预检环境", b.sub)
    }

    @Test
    fun failureBeatsRooted() {
        val b = bannerFor(ShellState.CONNECTED, rooted = true, busy = false, stage = "", lastFail = "CHAIN_STOP:check_uid0")
        assertEquals("未成功", b.title)
        assertEquals(BannerAction.SHOW_LOG, b.action)
    }

    @Test
    fun failureWithoutShellAsksForPermission() {
        val b = bannerFor(ShellState.NO_PERM, rooted = false, busy = false, stage = "", lastFail = "CHAIN_STOP:check_uid0")
        assertEquals("需要授权", b.title)
        assertEquals(BannerAction.REQUEST_PERM, b.action)
    }

    @Test
    fun rootedShowsOpenManager() {
        val b = bannerFor(ShellState.CONNECTED, rooted = true, busy = false, stage = "", lastFail = null)
        assertEquals("已提权", b.title)
        assertEquals(BannerAction.OPEN_MANAGER, b.action)
    }

    @Test
    fun bootSuccessShowsRootedWithoutShizuku() {
        // 9.384: 本次开机已成功过，Shizuku 没起来也显示已提权，并且能点开管理器
        val b = bannerFor(
            ShellState.ABSENT, rooted = false, busy = false, stage = "", lastFail = null,
            succeededThisBoot = true, okManagerPkg = "com.sukisu.nova",
        )
        assertEquals("已提权", b.title)
        assertEquals(BannerAction.OPEN_MANAGER, b.action)
    }

    @Test
    fun bootSuccessWithoutManagerStaysQuiet() {
        val b = bannerFor(
            ShellState.ABSENT, rooted = false, busy = false, stage = "", lastFail = null,
            succeededThisBoot = true, okManagerPkg = null,
        )
        assertEquals("已提权", b.title)
        assertEquals(BannerAction.NONE, b.action)
    }

    @Test
    fun authFailuresClearOnceGranted() {
        // 9.338: 授权类失败在授权成功后要能被 refresh() 清掉，否则横幅永远停在「需要授权」
        assertTrue(isAuthFail("unauthorized. auth prompt shown; allow it then tap Start again"))
        assertTrue(isAuthFail("start Shizuku and grant access first"))
        assertTrue(isAuthFail("Shizuku 未运行"))
        assertTrue(isAuthFail("permission denied"))
        // 链路本身的失败是证据，不能被授权清掉
        assertFalse(isAuthFail("CHAIN_STOP:check_uid0"))
        assertFalse(isAuthFail("self cell install failed"))
        assertFalse(isAuthFail("no root manager detected; long-press the manager row to pick one"))
    }

    @Test
    fun authBannerInvitesTheShizukuApp() {
        val b = bannerFor(ShellState.NO_PERM, rooted = false, busy = false, stage = "", lastFail = null)
        assertTrue(b.sub.contains("Shizuku"))
        assertTrue(b.sub.contains("刷新"))
    }

    @Test
    fun autoOpenNeedsRootAndPackage() {
        assertTrue(shouldAutoOpenManager(ok = true, rooted = true, pkg = "io.milksu.manager"))
        assertFalse(shouldAutoOpenManager(ok = true, rooted = false, pkg = "io.milksu.manager"))
        assertFalse(shouldAutoOpenManager(ok = false, rooted = true, pkg = "io.milksu.manager"))
        assertFalse(shouldAutoOpenManager(ok = true, rooted = true, pkg = null))
        assertFalse(shouldAutoOpenManager(ok = true, rooted = true, pkg = "  "))
    }

    @Test
    fun backendLabelFollowsPref() {
        // 9.323: the chain list shows the vulnerability number plus its principle, so the
        // backend label carries the CVE id instead of the internal chain id.
        assertEquals("CVE-2026-98937 · perf 标定", backendOf(prefCalib = true))
        assertEquals("CVE-2026-98260 · posix timer UAF", backendOf(prefCalib = false))
        // 9.333: with no mode given the label follows the new default branch.
        assertEquals("CVE-2026-99491 · no-tracefs 分支", backendOf(prefCalib = false, wacom = true))
        assertEquals("CVE-2026-99491 · real_cred 分支",
            backendOf(prefCalib = false, wacom = true, wacomMode = "real_cred"))
        assertEquals("CVE-2026-99491 · tracefs 分支",
            backendOf(prefCalib = false, wacom = true, wacomMode = "tracefs"))
        assertEquals("CVE-2026-99491 · no-tracefs 分支",
            backendOf(prefCalib = false, wacom = true, wacomMode = "no-tracefs"))
        assertEquals("CVE-2026-98260 · ghost 链", backendOf(prefCalib = false, ghost = true))
    }
}
