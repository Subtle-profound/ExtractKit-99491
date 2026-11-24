package com.extractkit.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 判定规则的回归测试。
 *
 * 这些用例直接对应真实日志里的两种翻车：
 *   - `su → uid=?` 但 `[+] child report uid=0` + `kernelsu → kernelsu 442368 5`
 *     → 应判成功（管理器未授权 su，不是 exploit 失败）；
 *   - `kernelsu →（无）` 之类不带 uid=0 的字符串 → 不能判成功。
 */
class VerdictTest {

    private val suOk = listOf(
        "id → uid=2000(shell) gid=2000(shell)",
        "su → uid=0(root) gid=0(root) context=u:r:ksu:s0",
        "kernelsu → kernelsu 442368 2",
    )

    private val suDeniedKsuLoaded = listOf(
        "id → uid=2000(shell) gid=2000(shell)",
        "su → uid=? gid=?          context=?",
        "kernelsu → kernelsu 442368 5",
    )

    private val nothing = listOf(
        "id → uid=2000(shell) gid=2000(shell)",
        "su → uid=? gid=?          context=?",
        "kernelsu → (无)",
    )

    @Test
    fun suUid0IsSuccess() {
        assertTrue(Verdict.rooted(suOk, "child report uid=0", true))
    }

    @Test
    fun childReportWithKsuIsSuccess() {
        // 这正是 22:5x 那份日志的形态：su 没授权，但凭据已改、模块已加载
        assertTrue(Verdict.rooted(suDeniedKsuLoaded, Verdict.MARKER_CHILD_UID0, true))
    }

    @Test
    fun childReportAloneIsSuccess() {
        // 只看最后是不是 uid=0：payload 读回 resuid=0/0/0 就算成功，
        // 不再要求 kernelsu 已加载（那是管理器层面的事）。
        assertTrue(Verdict.rooted(nothing, Verdict.MARKER_CHILD_UID0, true))
    }

    @Test
    fun payloadFailedIsNotSuccess() {
        assertFalse(Verdict.rooted(suDeniedKsuLoaded, Verdict.MARKER_CHILD_UID0, false))
    }

    @Test
    fun weakMarkerIsNotSuccess() {
        assertFalse(Verdict.rooted(nothing, "kernelsu", false))
    }

    @Test
    fun summaryExplainsSuAuthorization() {
        val s = Verdict.summary(suDeniedKsuLoaded, Verdict.MARKER_CHILD_UID0, true)
        assertTrue(s.contains("authorize su in the manager"))
        assertTrue(Verdict.summary(suOk, "child report uid=0", true).contains("su available"))
    }
}
