package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * 9.293：只有真 uuid 才算 boot_id。
 *
 * 9.104 那代把异常文本当 boot_id（日志里的 `boot_id=java.io.`），还会写进 last_ok_boot。
 */
class BootIdGuardTest {

    private val uuid = "f90dcdbd-1a2b-4c3d-8e9f-001122334455"

    @Test
    fun acceptsRealUuid() {
        assertEquals(uuid, ExtractEngine.bootIdOf(uuid))
        assertEquals(uuid, ExtractEngine.bootIdOf("  " + uuid + "\n"))
    }

    @Test
    fun rejectsExceptionText() {
        assertEquals("", ExtractEngine.bootIdOf("java.io.IOException: Cannot run program \"sh\""))
        assertEquals("", ExtractEngine.bootIdOf("java.io."))
    }

    @Test
    fun rejectsEmptyAndPartial() {
        assertEquals("", ExtractEngine.bootIdOf(""))
        assertEquals("", ExtractEngine.bootIdOf("0"))
        assertEquals("", ExtractEngine.bootIdOf("f90dcdbd"))
    }

    @Test
    fun rejectsUppercaseAndBadLength() {
        assertEquals("", ExtractEngine.bootIdOf(uuid.uppercase()))
        assertEquals("", ExtractEngine.bootIdOf(uuid.dropLast(1)))
    }
}
