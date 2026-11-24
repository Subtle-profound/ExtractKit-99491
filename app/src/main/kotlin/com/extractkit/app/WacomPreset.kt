/**
 * 9.300：EK-W1 载荷的 --build 选择。
 *
 * payload 里每支内核一个预设（SYM_UHID_WORKER + 三处 alloc call site 逐 build 不同），
 * 用 strstr 在传入串里找 build 标识。9.299 传的是 6.6.118-g5549 —— 不含 g-hash，
 * strstr 全部落空，payload 静默用编死的默认预设（另一支 6.6.118），worker 符号错 0x34c0，
 * slide 不 2MB 对齐，整轮 spray 只打 trace pairs=0，最后 no reachable child cred。
 * 因此这里必须原样把内核 release 串（含 g-hash）传下去。
 */
internal object WacomPreset {
    /** payload 侧 --build 能识别的 build 标识（与 exp.c 的 strstr 别名表对应）。 */
    val BUILDS = listOf("554929766a0d")

    /** kernel release -> --build 参数；null 表示不加 --build（用 payload 的默认预设）。 */
    fun pick(kernel: String): String? =
        if (BUILDS.any { kernel.contains(it) }) kernel else null
}