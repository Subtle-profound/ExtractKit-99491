package com.extractkit.app

/**
 * 9.293：把 shell 层故障分成可判读的几类。
 *
 * 背景：9.104 那一代的日志里只出现 `boot_id=java.io.` 和 `NO_TRACEFS` —— 真正的原因是
 * 服务进程 fork 不出 `sh`（cwd 不可 chdir / sh 不可执行 / fd 耗尽），probe() 一个字都
 * 拿不回来，于是被 `!env.tracefs` 误报成「tracefs 不可写」。这里集中判定，日志不再猜。
 */
object ShellFailure {

    /** 只在 ProcessBuilder.start() 真失败时出现的特征。 */
    private val SPAWN_MARKS = listOf(
        "Cannot run program",
        "cannot fork sh",
        "error=13",
        "error=2",
        "Too many open files",
    )

    fun isSpawn(text: String): Boolean =
        SPAWN_MARKS.any { text.contains(it, ignoreCase = true) }

    fun kind(text: String): String = when {
        text.isBlank() -> "SHELL_ERROR"
        isSpawn(text) -> "SHELL_SPAWN_FAILED"
        text.contains("未连接") ||
            text.contains("not connected", ignoreCase = true) ||
            text.contains("UserService disconnected", ignoreCase = true) -> "SHELL_NOT_CONNECTED"
        text.contains("DeadObject", ignoreCase = true) ||
            text.contains("binder", ignoreCase = true) -> "SHELL_BINDER_DEAD"
        else -> "SHELL_ERROR"
    }

    /** 一行化并截断，日志里只留可读的那部分（保留原始异常类名与 message）。 */
    fun summary(text: String, limit: Int = 400): String {
        val one = text.replace('\n', ' ').replace('\r', ' ').trim()
            .replace(Regex("\\s+"), " ")
        return if (one.length <= limit) one else one.substring(0, limit) + "…"
    }
}
