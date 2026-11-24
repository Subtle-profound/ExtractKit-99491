package com.extractkit.app

/**
 * ghost 链的内核匹配（m24099「不匹配内核就不跑」/ m24118「主要目的是跑那两个内核」）。
 *
 * 与 C 侧 ghost_map_pick 同一判据：profile 必须是 uname -r 的前缀，
 * 且紧随其后的字符是 '-' 或字符串结束。命中不了就返回 null —— 调用方必须拒跑，
 * 绝不允许拿别的 build 的常量顶替（写错 .data 会直接 Oops，panic_on_oops=1 整机重启）。
 */
internal object GhostSupport {
    fun profileFor(kernel: String, known: Set<String> = GhostCalibrated.RELEASES): String? {
        if (kernel.isEmpty()) return null
        return known.firstOrNull { k ->
            k.isNotEmpty() && kernel.length >= k.length && kernel.startsWith(k) &&
                (kernel.length == k.length || kernel[k.length] == '-')
        }
    }
}
