package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * 9.406: every built-in 99491 profile must ship a ko-syms table for the same release.
 *
 * The payload refuses to arm when ko_syms_check() rejects the table, so a profile without a
 * table is a dead entry that fails on the phone instead of here. The check is structural:
 * format 1, kernel_release equal to the profile's release, symbol_count equal to the real
 * row count, plus the pinned size/sha of the asset.
 */
class WacomSymsCoverageTest {

    private val assets = File("src/main/assets")

    private fun sha256(b: ByteArray): String {
        val d = MessageDigest.getInstance("SHA-256").digest(b)
        val sb = StringBuilder(d.size * 2)
        for (x in d) sb.append(String.format("%02x", x.toInt() and 0xff))
        return sb.toString()
    }

    @Test
    fun everyBuiltinReleaseHasATable() {
        assumeTrue("assets 不在预期位置: " + assets.absolutePath, assets.isDirectory)
        val missing = WacomBuiltin.ENTRIES.map { it.release }
            .filter { ExtractEngine.SYMS_BY_RELEASE[it] == null }
        assertTrue("no ko-syms table for: " + missing, missing.isEmpty())
        val extra = ExtractEngine.SYMS_BY_RELEASE.keys
            .filter { k -> WacomBuiltin.ENTRIES.none { it.release == k } }
        assertTrue("table without a profile: " + extra, extra.isEmpty())
    }

    @Test
    fun everyTableIsPinnedAndMatchesItsHeader() {
        assumeTrue("assets 不在预期位置: " + assets.absolutePath, assets.isDirectory)
        for (e in WacomBuiltin.ENTRIES) {
            val t = ExtractEngine.SYMS_BY_RELEASE[e.release]
            assertNotNull("no table for " + e.release, t)
            val asset = t!!.first
            val f = File(assets, asset)
            assertTrue("missing table asset: " + asset, f.isFile)
            val bytes = f.readBytes()
            assertEquals("size of " + asset, t.second, bytes.size)
            assertEquals("sha256 of " + asset, t.third, sha256(bytes))

            val lines = String(bytes, Charsets.UTF_8).lines()
            val format = lines.firstOrNull { it.startsWith("# format:") }?.substringAfter(':')?.trim()?.toIntOrNull()
            val release = lines.firstOrNull { it.startsWith("# kernel_release:") }?.substringAfter(':')?.trim()
            val declared = lines.firstOrNull { it.startsWith("# symbol_count:") }?.substringAfter(':')?.trim()?.toIntOrNull()
            val rows = lines.count { it.isNotBlank() && !it.startsWith("#") }
            assertEquals("format of " + asset, 1, format)
            assertEquals("kernel_release of " + asset, e.release, release)
            assertEquals("symbol_count of " + asset, rows, declared)
            assertTrue("table " + asset + " has no rows", rows > 200)
        }
    }
}
