package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * 9.457: cred_jar 是 `kmem_cache_create("cred_jar", sizeof(struct cred), 0,
 * SLAB_HWCACHE_ALIGN|…)`，SLAB_HWCACHE_ALIGN 按 cache line（arm64 64 B）向上
 * 取整，所以 CRED_ALLOC 必须是 64 对齐；早先的 16 对齐会在
 * sizeof(struct cred) = 200 这类尺寸上算成 0xD0（真实是 0x100）。
 */
class CredSlabTest {
    @Test
    fun credSlabIsCacheLineAligned() {
        assertEquals(0xC0, ConfigGen.credSlabObjectBytes(0xB8))
        assertEquals(0xC0, ConfigGen.credSlabObjectBytes(0xB0))
        assertEquals(0x100, ConfigGen.credSlabObjectBytes(0xC8))
        assertEquals(0x100, ConfigGen.credSlabObjectBytes(0x100))
        assertEquals(0x80, ConfigGen.credSlabObjectBytes(0x70))
    }
}
