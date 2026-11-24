package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * 9.354: the legacy layouts that the calibration page claims to reject must actually parse.
 * The 5.15.194 image uses the pre-6.4 order (offsets | relative base | names | markers).
 */
class Kallsyms5Test {
    private val imgPath = "D:/deepseek work/refdata/boot_5.15.194-gd1cdcc28f0f7.kernel"

    @Test
    fun parsesA515Image() {
        val f = File(imgPath)
        assumeTrue("no " + imgPath, f.isFile)
        val logs = ArrayList<String>()
        val r = KallsymsFinder.find(f.readBytes()) { logs.add(it) }
        println("LOG:: " + logs.joinToString(" / "))
        assertNotNull("finder returned null", r)
        val got = requireNotNull(r)
        println("COUNT:: " + got.numSyms + " base=0x" + java.lang.Long.toHexString(got.relativeBase) +
            " syms=" + got.symbols.size + " markers=0x" + Integer.toHexString(got.markersOffset))
        for (k in listOf(
            "_text", "_stext", "prepare_creds", "selinux_state", "init_cred",
            "input_inject_event", "input_handle_events_default", "runqueues",
            "input_dev_list", "__per_cpu_offset", "kmem_cache_alloc",
            "uhid_device_add_worker", "cap_last_cap",
        )) {
            val v = got.symbols[k]
            println("SYM:: " + k + " = " + (if (v == null) "MISSING" else "0x" + java.lang.Long.toHexString(v)))
        }
        assertTrue("no prepare_creds", got.symbols.containsKey("prepare_creds"))
        assertTrue("too few symbols: " + got.symbols.size, got.symbols.size > 50000)
        // _text must sit at or just above relativeBase
        val text = got.symbols["_text"] ?: got.symbols["_stext"]
        assertNotNull("no _text", text)
        val d = requireNotNull(text) - got.relativeBase
        assertTrue("_text - base = " + d, d in 0..0x200000)
    }
}
