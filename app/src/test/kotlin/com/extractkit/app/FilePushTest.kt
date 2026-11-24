package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 9.294：分块推送的边界（首块截断、末块打 mode、总量守恒）。 */
class FilePushTest {

    @Test
    fun smallFileIsOneTruncatingPart() {
        val p = FilePush.plan(100, 256)
        assertEquals(1, p.size)
        assertEquals(0, p[0].offset)
        assertEquals(100, p[0].len)
        assertTrue(p[0].truncate)
        assertTrue(p[0].last)
    }

    @Test
    fun exactMultipleKeepsLastFlagOnFinalPart() {
        val p = FilePush.plan(512, 256)
        assertEquals(2, p.size)
        assertTrue(p[0].truncate)
        assertEquals(false, p[1].truncate)
        assertEquals(false, p[0].last)
        assertTrue(p[1].last)
    }

    @Test
    fun remainderIsItsOwnPart() {
        val p = FilePush.plan(1000, 256)
        assertEquals(4, p.size)
        assertEquals(768, p[3].offset)
        assertEquals(232, p[3].len)
        assertTrue(p[3].last)
    }

    @Test
    fun totalIsPreserved() {
        for (total in listOf(1, 255, 256, 257, 476048, 6470288)) {
            assertEquals(total, FilePush.plan(total).sumOf { it.len })
        }
    }

    @Test
    fun emptyFileStillTruncates() {
        val p = FilePush.plan(0)
        assertEquals(1, p.size)
        assertTrue(p[0].truncate)
        assertTrue(p[0].last)
        assertEquals(0, p[0].len)
    }
}
