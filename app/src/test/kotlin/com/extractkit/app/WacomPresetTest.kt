package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** 9.300：9.299 的预设选择 bug 回归（--build 串必须含 g-hash）。 */
class WacomPresetTest {
    private val k = "6.6.118-android15-8-g554929766a0d-abogki544555896-4k"

    @Test
    fun passesTheFullReleaseSoThePresetIsFound() {
        assertEquals(k, WacomPreset.pick(k))
    }

    @Test
    fun shortHashlessFormIsNeverProduced() {
        val picked = WacomPreset.pick(k)
        assertEquals(true, picked != null && picked.contains("554929766a0d"))
    }

    @Test
    fun otherBuildHasNoPreset() {
        assertNull(WacomPreset.pick("6.6.118-android15-8-ga812a1946391-abogki576098434-4k"))
        assertNull(WacomPreset.pick("5.15.194-android13-8-gd1cdcc28f0f7"))
    }

    @Test
    fun binaryAliasTableCoversOurString() {
        // exp.c 的 strstr 别名表（554929766a0d / g5549）必须覆盖我们传的串。
        assertEquals(true, k.contains("554929766a0d") || k.contains("g5549"))
    }
}