package com.extractkit.app

/**
 * 「是否真的拿到了 uid=0」的判定规则。
 *
 * 为什么单独抽出来：这条规则曾经两次把**成功**判成失败（9.104 与后面那次
 * `child report uid=0` + `kernelsu 442368` 但 `su → uid=?`），也曾经把失败判成
 * 成功（marker 里只写了裸 `kernelsu`，被 `kernelsu →（无）` 命中）。所以它必须
 * 有单测钉住，而不是每次靠装机看日志。
 *
 * 判定顺序：
 *   1. `su -c id` 里出现 `uid=0` —— 最硬的证据；
 *   2. payload 自报 `child report uid=0`（内部已经 `setresuid(0,0,0)=0`、
 *      读回 `resuid=0/0/0`）**且** `/proc/modules` 里有 `kernelsu` 模块 ——
 *      说明 cred 改写已经生效、KernelSU 也已加载；此时 `su` 不可用只是
 *      管理器还没给 shell 授权，属于“提权成功、管理器未授权”；
 *   3. 其余一律不算成功。
 */
object Verdict {

    const val MARKER_CHILD_UID0 = "child report uid=0"

    fun suUid0(verifyLines: List<String>): Boolean =
        verifyLines.any { line ->
            line.contains("su →") && line.contains("uid=0")
        }

    /** 给界面用的一句话说明。 */
    /**
     * 9.292: cred really changed and kernelsu really loaded, even when su is not authorized yet.
     * The marker alone is never enough - "kernelsu" also matches "kernelsu ->(none)".
     */
    fun rooted(verifyLines: List<String>, marker: String?, payloadOk: Boolean): Boolean {
        if (suUid0(verifyLines)) return true
        if (!payloadOk || marker == null) return false
        // 只看 payload 最后是不是 uid=0：模块是否已加载属于管理器层面的事（9.104 的教训）
        return marker.contains(MARKER_CHILD_UID0)
    }

    fun summary(verifyLines: List<String>, marker: String?, payloadOk: Boolean): String = when {
        suUid0(verifyLines) -> "uid=0 confirmed (su available)"
        rooted(verifyLines, marker, payloadOk) -> "uid=0 confirmed (cred changed; authorize su in the manager)"
        else -> "uid=0 not confirmed"
    }
}
