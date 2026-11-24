package com.extractkit.app

/** 9.192: a debug switch carries the version that created it; a stale stamp is removed. */
data class DebugSwitch(val on: Boolean, val note: String?)

internal fun debugSwitch(path: String): DebugSwitch {
    val f = java.io.File(path)
    if (!f.isFile) return DebugSwitch(false, null)
    val s = runCatching { f.readText() }.getOrDefault("").trim()
    val now = BuildConfig.VERSION_NAME
    return if (s == now) {
        DebugSwitch(true, "\u00b7 debug switch " + f.name + " active (stamp " + s + "): forces that payload form")
    } else {
        runCatching { f.delete() }
        DebugSwitch(
            false,
            "\u00b7 debug switch " + f.name + " stale (" + (if (s.isEmpty()) "no version stamp" else "stamp is " + s) +
                ", now " + now + "): removed; default selection used",
        )
    }
}
