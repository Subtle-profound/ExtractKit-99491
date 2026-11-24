package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** 9.291：stage 的候选排名行解析 / 排序。样本行照抄脚本真实输出格式。 */
class CandidateRankTest {

    private val sample = listOf(
        "[resolve] cand libksud_ksu.so score=37 size=1843560 caps=pn1,pm1,uid1",
        "[resolve] cand libxeccoresu.so score=12 size=148024 caps=pn0,pm0,uid0",
        "[resolve] cand libghostlock.so score=44 size=92168 caps=pn1,pm0,uid0",
        "some unrelated stage line",
    )

    @Test
    fun parsesNameScoreSize() {
        val all = CandidateRank.parse(sample)
        assertEquals(3, all.size)
        val ksud = all.first { it.name == "libksud_ksu.so" }
        assertEquals(37, ksud.score)
        assertEquals(1843560L, ksud.size)
    }

    @Test
    fun higherScoreWins() {
        assertEquals("libghostlock.so", CandidateRank.best(sample)?.name)
        assertEquals(listOf("libghostlock.so", "libksud_ksu.so", "libxeccoresu.so"), CandidateRank.order(sample))
    }

    @Test
    fun equalScorePrefersBiggerBinary() {
        val lines = listOf(
            "[resolve] cand small.so score=20 size=10 caps=pn1",
            "[resolve] cand big.so score=20 size=999 caps=pn1",
        )
        assertEquals("big.so", CandidateRank.best(lines)?.name)
    }

    @Test
    fun ignoresLinesWithoutScore() {
        val lines = listOf("[resolve] cand broken.so size=5", "[resolve] scanned 3 dir(s)")
        assertTrue(CandidateRank.parse(lines).isEmpty())
        assertNull(CandidateRank.best(lines))
    }

    @Test
    fun capsSuffixDoesNotLeakIntoSize() {
        val one = CandidateRank.parse(listOf("[resolve] cand a.so score=5 size=7 caps=pn1"))[0]
        assertEquals(7L, one.size)
    }
}
