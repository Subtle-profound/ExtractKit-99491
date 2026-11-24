package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Test

/** 9.290：管理器 appid 注册状态的判定必须能从日志一眼看出“到底注册成谁了”。 */
class ManagerRegistrationTest {

    private val map = "dev.maplesu.manager"
    private val xec = "com.xecpro.kernel"
    private val ksu = "me.weishu.kernelsu"
    private val none = listOf("(no parameters dir: /sys/module/kernelsu/parameters)")

    @Test
    fun kernelReadbackWins() {
        val params = listOf("package_name=$map", "version=31413")
        assertEquals("registered($map:10123)", ManagerVerdict.of(map, "$map:10123", params, 1, "LATE_EXIT=0"))
    }

    @Test
    fun kernelReadbackShowsTheWrongManager() {
        val params = listOf("package_name=$ksu")
        assertEquals(
            "registered($ksu, NOT $map)",
            ManagerVerdict.of(map, "", params, 1, "LATE_EXIT=4"),
        )
    }

    @Test
    fun markerOnlyIsRegisteredButUnverified() {
        assertEquals(
            "registered-unverified($map:10123)",
            ManagerVerdict.of(map, "$map:10123", none, 1, "LATE_EXIT=0"),
        )
    }

    @Test
    fun noInPackageKsudIsItsOwnState() {
        assertEquals("no-ksud($xec)", ManagerVerdict.of(xec, "", none, 1, "LATE_EXIT=5"))
        assertEquals("no-ksud($xec)", ManagerVerdict.of(xec, "", none, 1, "5"))
    }

    @Test
    fun moduleLoadedWithoutReadbackIsOnlyUnverified() {
        assertEquals("unverified", ManagerVerdict.of(map, "", none, 1, "LATE_EXIT=0"))
    }

    @Test
    fun nothingLoadedIsFailed() {
        assertEquals("FAILED", ManagerVerdict.of(map, "", none, 0, "LATE_EXIT=0"))
    }
}
