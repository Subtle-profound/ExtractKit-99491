package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class WacomSymsTest {

    private val template = """
        # format: 1
        # kernel_release: 6.6.118-android15-8-g554929766a0d-abogki544555896-4k
        # symbol_count: 3
        # note: link-time VAs; ko_patch adds the boot slide
        _printk ffffffc08055c014
        prepare_creds ffffffc0801f2938
        synchronize_rcu ffffffc08035a86c
    """.trimIndent()

    @Test
    fun namesSkipHeaders() {
        assertEquals(listOf("_printk", "prepare_creds", "synchronize_rcu"), WacomSyms.names(template))
    }

    @Test
    fun buildRewritesHeaderAndAddresses() {
        // hex literals above Long.MAX_VALUE are rejected by the compiler, so parse as unsigned
        val addrs = mapOf(
            "_printk" to java.lang.Long.parseUnsignedLong("ffffffc0800d3710", 16),
            "prepare_creds" to java.lang.Long.parseUnsignedLong("ffffffc08019b1d0", 16),
        )
        val b = WacomSyms.build(template, "6.12.58-android16-6-gdf8d34cadbf7-abogki584560711-4k", addrs)
        assertEquals(2, b.symbols)
        assertEquals(listOf("synchronize_rcu"), b.missing)
        assertTrue(b.text.contains("# kernel_release: 6.12.58-android16-6-gdf8d34cadbf7-abogki584560711-4k"))
        assertTrue(b.text.contains("# symbol_count: 2"))
        assertTrue(b.text.contains("_printk ffffffc0800d3710"))
        assertTrue(!b.text.contains("synchronize_rcu"))
    }

    @Test
    fun familyPicksTemplate() {
        assertTrue(WacomSyms.templateAsset("6.12").contains("6.12"))
        assertTrue(WacomSyms.templateAsset("6.6").endsWith("ko-syms.txt"))
        assertTrue(WacomSyms.templateAsset(null).endsWith("ko-syms.txt"))
    }

    @Test
    fun releaseIsReadBackFromHeader() {
        val txt = WacomSyms.build(template, "6.1.99-android14-11-gdeadbeef-ab1-4k", emptyMap()).text
        assertEquals("6.1.99-android14-11-gdeadbeef-ab1-4k",
            WacomCalibStore.symsReleaseIn(txt.toByteArray(Charsets.UTF_8)))
    }
}
