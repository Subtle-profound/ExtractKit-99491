package com.extractkit.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 9.407: App 侧与 payload 里 rel_same_build() 必须同一套判据。 */
class RelMatchTest {

    private val base = "6.6.118-android15-8-g554929766a0d-abogki544555896-4k"

    @Test
    fun exactStringMatches() {
        assertTrue(RelMatch.same(base, base))
    }

    @Test
    fun otherBuildStampOfTheSameBuildMatches() {
        assertTrue(RelMatch.same(base, "6.6.118-android15-8-g554929766a0d-abogki999999999-4k"))
        assertTrue(RelMatch.same("6.6.118-android15-8-g554929766a0d-abogki999999999-4k", base))
        assertTrue(RelMatch.same(base, "6.6.118-android15-8-g554929766a0d"))
    }

    @Test
    fun differentGitHashIsAnotherKernel() {
        assertFalse(RelMatch.same(base, "6.6.118-android15-8-ga812a1946391-abogki576098434-4k"))
        assertFalse(RelMatch.same("6.6.118-android15-8-ga812a1946391-abogki576098434-4k", base))
    }

    @Test
    fun differentVersionIsAnotherKernel() {
        assertFalse(RelMatch.same(base, "6.6.89-android15-8-g554929766a0d-abogki544555896-4k"))
        assertFalse(RelMatch.same(base, "6.12.58-android16-6-g554929766a0d-abogki544555896-4k"))
        assertFalse(RelMatch.same(base, "6.1.128-android14-11-g554929766a0d"))
    }

    @Test
    fun emptySideNeverMatches() {
        assertFalse(RelMatch.same("", base))
        assertFalse(RelMatch.same(base, ""))
    }

    @Test
    fun shortOrNonHashSuffixDoesNotCutComparison() {
        assertFalse(RelMatch.same("6.6.118-android15-8", "6.6.118-android15-8-g554929766a0d"))
        assertFalse(RelMatch.same("6.6.118-android15-8-g5549297", "6.6.118-android15-8-g554929766a0d"))
    }
}
