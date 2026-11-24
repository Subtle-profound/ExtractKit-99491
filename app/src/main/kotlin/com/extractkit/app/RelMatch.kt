package com.extractkit.app

/**
 * 9.407: uname -r 的「同一颗内核」判据，与 payload 里 `rel_same_build()` 同一套规则 ——
 * 只比前面几段（版本 / androidN / g<hash>），遇到 git hash 段就认为已经定位到 build，
 * 忽略 `-abogkiNNNNNNNNN-4k` 这类本地构建戳。
 *
 * 为什么要和 C 侧一致：C 侧已经把 syms 预检与 profile 预检放宽到这条规则，App 侧若还按
 * 全串相等取 profile/syms，同一颗内核换个构建戳就会先被 App 拦在 WACOM_UNMATCHED，
 * 放宽等于白改。
 *
 * 反过来说，g<hash> 不同（或版本段不同）一律不算同一颗 —— 那是另一次编译，偏移会错。
 */
internal object RelMatch {

    fun same(a: String, b: String): Boolean {
        if (a.isEmpty() || b.isEmpty()) return false
        if (a == b) return true
        val xs = a.split('-')
        val ys = b.split('-')
        val n = minOf(xs.size, ys.size)
        for (i in 0 until n) {
            val x = xs[i]
            val y = ys[i]
            if (x != y) return false
            if (isGitHash(x)) return true
        }
        return xs.size == ys.size
    }

    /** "g554929766a0d" 这样的段：g + 至少 8 位 [0-9a-f]。 */
    private fun isGitHash(s: String): Boolean {
        if (s.length < 9 || s[0] != 'g') return false
        for (i in 1 until s.length) {
            val c = s[i]
            if (c !in '0'..'9' && c !in 'a'..'f') return false
        }
        return true
    }
}
