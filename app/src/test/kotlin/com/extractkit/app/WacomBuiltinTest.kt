package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * 9.354: every entry of the built-in 99491 profile table has to be the byte-exact JSON that
 * was derived from that kernel, pass the payload's own validate() rules, and carry the same
 * release string the payload strcmp()s against. A wrong table entry ships wrong cred offsets,
 * so this is checked in CI rather than on the phone.
 */
class WacomBuiltinTest {

    private val assets = File("src/main/assets")

    private fun sha256(b: ByteArray): String {
        val d = MessageDigest.getInstance("SHA-256").digest(b)
        val sb = StringBuilder(d.size * 2)
        for (x in d) sb.append(String.format("%02x", x.toInt() and 0xff))
        return sb.toString()
    }

    @Test
    fun everyEntryMatchesItsPinnedBytes() {
        assumeTrue("assets 不在预期位置: " + assets.absolutePath, assets.isDirectory)
        assertTrue("built-in table is empty", WacomBuiltin.ENTRIES.isNotEmpty())
        for (e in WacomBuiltin.ENTRIES) {
            val f = File(assets, e.asset)
            assertTrue("missing asset: " + e.asset, f.isFile)
            val b = f.readBytes()
            assertEquals("size of " + e.asset, e.size, b.size)
            assertEquals("sha256 of " + e.asset, e.sha256, sha256(b))
        }
    }

    @Test
    fun everyEntryIsAValidProfileForItsOwnRelease() {
        assumeTrue("assets 不在预期位置: " + assets.absolutePath, assets.isDirectory)
        val re = Regex("\"release\"\\s*:\\s*\"([^\"]*)\"")
        for (e in WacomBuiltin.ENTRIES) {
            val json = File(assets, e.asset).readText()
            val release = re.find(json)?.groupValues?.get(1)
            assertEquals("release inside " + e.asset, e.release, release)
            val problems = WacomCalib.validate(json)
            assertTrue(e.asset + " is not a valid profile: " + problems, problems.isEmpty())
        }
    }

    @Test
    /**
     * 9.407: 判据从「全串相等」放宽到「版本 + g<hash>」（RelMatch，与 payload 的
     * rel_same_build() 同规则）。不同构建戳仍算同一颗；g<hash> 或版本不同一律不算。
     */
    fun lookupIsPerBuildNotPrefix() {
        val k = "6.6.118-android15-8-g554929766a0d-abogki544555896-4k"
        assertTrue("exact: " + k, WacomBuiltin.forKernel(k) != null)
        // 同一颗内核、只换了本地构建戳
        assertTrue("same build + suffix", WacomBuiltin.forKernel(k + "-x") != null)
        assertTrue("same build, other stamp", WacomBuiltin.forKernel("6.6.118-android15-8-g554929766a0d-abogki123456789-4k") != null)
        // 不够定位到 build 的裸前缀仍然不算
        assertTrue("bare prefix", WacomBuiltin.forKernel("6.6.118-android15-8") == null)
        // 另一颗内核
        // 换 hash 就是另一颗内核（用不在内置表里的 hash，免得命中的是它自己的条目）
        assertTrue("other hash", WacomBuiltin.forKernel("6.6.118-android15-8-gdeadbeef00-abogki576098434-4k") == null)
        assertTrue(WacomBuiltin.forKernel("6.9.9-android16-0-gdeadbeef") == null)
    }
}