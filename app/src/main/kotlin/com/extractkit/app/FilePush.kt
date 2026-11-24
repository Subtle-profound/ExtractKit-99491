package com.extractkit.app

/**
 * 9.294：把一次大文件推送切成若干块。
 *
 * 为什么要切：binder 单次事务上限约 1 MiB，476 KB 的 payload 一次塞不下；
 * 为什么要「每块自带 truncate 标记」：Shizuku 的 binder wrapper 会在目标进程死掉时
 * **透明重连**到新进程，新实例里没有任何状态 —— 旧协议靠 fileOpen/fileWrite/fileClose
 * 三步共享 sink，重连后 fileWrite 只能抛 "fileOpen() 还没调用"（9.293 真机日志）。
 * 所以每块都自带「第一块就截断，其余追加」，断在哪块都不影响最终内容。
 */
object FilePush {

    data class Part(val offset: Int, val len: Int, val truncate: Boolean, val last: Boolean)

    fun plan(total: Int, step: Int = 256 * 1024): List<Part> {
        if (total <= 0) return listOf(Part(0, 0, true, true))
        require(step > 0) { "step must be positive" }
        val parts = ArrayList<Part>(total / step + 1)
        var offset = 0
        while (offset < total) {
            val len = minOf(step, total - offset)
            parts.add(Part(offset, len, offset == 0, offset + len >= total))
            offset += len
        }
        return parts
    }
}
