package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 9.293：shell 层故障分类。
 *
 * 样本照抄真机/ProcessBuilder 的原话，用来钉住「fork 不出 sh」不再被当成别的错。
 */
class ShellFailureTest {

    private val spawn = "java.io.IOException: Cannot run program \"sh\" (in directory \"" +
        "/data/local/tmp/extract-kit\"): error=13, Permission denied"

    @Test
    fun cwdPermissionDeniedIsSpawnFailure() {
        assertTrue(ShellFailure.isSpawn(spawn))
        assertEquals("SHELL_SPAWN_FAILED", ShellFailure.kind(spawn))
    }

    @Test
    fun missingShBinaryIsSpawnFailure() {
        val text = "java.io.IOException: Cannot run program \"sh\": error=2, No such file or directory"
        assertTrue(ShellFailure.isSpawn(text))
        assertEquals("SHELL_SPAWN_FAILED", ShellFailure.kind(text))
    }

    @Test
    fun fdExhaustionIsSpawnFailure() {
        val text = "java.io.IOException: error=24, Too many open files"
        assertTrue(ShellFailure.isSpawn(text))
        assertEquals("SHELL_SPAWN_FAILED", ShellFailure.kind(text))
    }

    @Test
    fun disconnectedServiceIsNotSpawnFailure() {
        val text = "UserService 未连接"
        assertFalse(ShellFailure.isSpawn(text))
        assertEquals("SHELL_NOT_CONNECTED", ShellFailure.kind(text))
    }

    @Test
    fun deadBinderIsItsOwnKind() {
        val text = "android.os.DeadObjectException: transaction failed on small parcel"
        assertFalse(ShellFailure.isSpawn(text))
        assertEquals("SHELL_BINDER_DEAD", ShellFailure.kind(text))
    }

    @Test
    fun ordinaryCommandFailureIsNotSpawnFailure() {
        assertFalse(ShellFailure.isSpawn(""))
        assertFalse(ShellFailure.isSpawn("cat: /nope: Permission denied"))
        assertEquals("SHELL_ERROR", ShellFailure.kind(""))
    }

    @Test
    fun summaryIsOneLineAndBounded() {
        val long = "line one\nline two\r\n" + "x".repeat(600)
        val one = ShellFailure.summary(long)
        assertFalse(one.contains('\n'))
        assertFalse(one.contains('\r'))
        assertTrue(one.length <= 401)
        assertTrue(one.endsWith("…"))
    }
}
