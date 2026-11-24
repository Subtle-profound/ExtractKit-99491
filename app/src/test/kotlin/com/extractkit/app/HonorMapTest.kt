package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class HonorMapTest {

    @Test
    fun renderKeepsHeaderAndOneRowPerName() {
        val text = HonorMap.render(mapOf("init_task" to 0xFFFFFFC08215E280uL.toLong()), "k")
        assertTrue(text.startsWith("# extractkit-map v1\n"))
        assertTrue(text.contains("# kernel=k\n"))
        assertEquals(HonorMap.NAMES.size, text.lines().count { it.isNotBlank() } - 3)
    }

    @Test
    fun unknownSymbolsRenderAsZero() {
        val text = HonorMap.render(emptyMap(), "k")
        assertTrue(text.contains("# nsyms=0\n"))
        assertTrue(text.contains("\ninit_cred 0x0\n"))
    }

    /** FW135 那份 boot.img 解包出来的符号必须真的落进表里（9.161）。 */
    @Test
    fun fw135ProfileCarriesHonorSymbols() {
        val p = ConfigGen.profileFor("6.6.89-android15-8-g082e5a98dac1-abogki463734347-4k")
        assertNotNull(p)
        val syms = p!!.symbols
        assertEquals(0xFFFFFFC08215E280uL.toLong(), syms["init_task"])
        assertEquals(0xFFFFFFC082170698uL.toLong(), syms["init_cred"])
        assertEquals(0xFFFFFFC0823D2EC0uL.toLong(), syms["init_net"])
        val text = HonorMap.render(syms, "6.6.89")
        assertTrue(text.contains("init_cred 0xffffffc082170698\n"))
    }
}
