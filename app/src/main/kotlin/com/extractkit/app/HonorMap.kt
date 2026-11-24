package com.extractkit.app

/**
 * HONOR 链的符号加载表（我们自己的格式，9.159）。
 *
 * 为什么自己生成：参考实现（荣耀5系提权.apk）带一份 258 行的 perf.tbl，
 * 那是从它自己的 5.10.236 上导出的 kallsyms 地址——只对那一个 build 成立。
 * 我们把别人的地址表装进 APK，等于「跑在别的内核上时按错的地址写内存」，
 * 与「不得原样使用外部文件」的交付要求也冲突。
 *
 * 所以表改成现场生成：App 已经知道本机内核的符号地址（标定结果 / 内置
 * profile / BTF），这里只把它序列化成 payload 认得的文本，推到工作目录。
 * 表里查不到的符号写 0，payload 会回落到编译期常量或 offsets-only，不硬写。
 */
object HonorMap {

    /** 表名（HONOR 链的 loadmap= 指向它）。 */
    const val FILE = "honor.map"

    /**
     * 表里放哪些符号（9.180 精简）。
     *
     * 之前列的 14 个名字里，payload 真正查的只有两个：
     *   - honor_ic() 查 init_cred（chain_honor.c:644）
     *   - honor_se() 查 selinux_state（chain_honor.c:651）
     * honor_ksym() 只在传了 pcsym=/leftsym= 时才查（ChainPlan 不传）。
     * 其余 12 个名字从来没有任何读取点，写进表里只是让文件变长。
     */
    val NAMES: List<String> = listOf(
        "init_cred",
        "selinux_state",
        // 9.297：5.15 支的 UAF 链还查这两个（字符串见 fam 载荷 UAF-SYM-MISS 附近）。
        // 表里缺它们只会打 UAF-SYM-MISS 并回落到编译期常量，但补上能让链走同一条已验证路径。
        "sig_enforce",
        "modules_disabled",
    )

    /**
     * 生成表正文：首行是格式标记，随后 name 0xaddr。
     *
     * 9.177 起只写链自己要用的 14 个：收尾改成 ksud late-load 后，链不再
     * 自己装载 msm_perf.ko，模块的 225 个导入符号也就不需要了（9.176 的
     * 那段模块表随本轮移除）。
     */
    fun render(syms: Map<String, Long>, kernel: String): String {
        val known = NAMES.count { (syms[it] ?: 0L) != 0L }
        val sb = StringBuilder()
        sb.append("# extractkit-map v1\n")
        sb.append("# kernel=").append(kernel.ifBlank { "?" }).append('\n')
        sb.append("# nsyms=").append(known).append('\n')
        for (n in NAMES) {
            val a = syms[n] ?: 0L
            sb.append(n).append(' ').append("0x").append(java.lang.Long.toHexString(a))
            sb.append('\n')
        }
        return sb.toString()
    }

    /** 取本机可用的符号表：本机标定优先，其次内置 profile。 */
    fun symsForCurrentKernel(): Pair<Map<String, Long>, String>? {
        val cur = System.getProperty("os.version").orEmpty()
        val p = ConfigGen.profileFor(cur) ?: return null
        return p.symbols to cur
    }
}
