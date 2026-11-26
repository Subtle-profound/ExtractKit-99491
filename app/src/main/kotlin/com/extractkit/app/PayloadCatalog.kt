package com.extractkit.app

/** 随 APK 打包的 payload（assets/payload 下），sha256 与上游 assets/SHA256SUMS 一致。 */
data class Payload(
    val name: String,
    val asset: String,
    val sha256: String,
    val note: String,
)

object Payloads {
    // name 同时被当作设备侧文件名，必须是可读标识而不是某个旧二进制的 sha。
    // 9.281：整包回到 9.213 的字节（那是本机真机唯一成功过的一套）。
    // 6.6 走这里或走 PER_FAMILY["6.6"]（同一份 476,048 B 的标定支）；
    // 其余分支命中 PER_FAMILY 时用分支自己的二进制。
    val UID0 = Payload(
        "ek-core-uid0",
        "payload/ek-core-uid0",
        "2e2f67efb508db1efa1651997c26dc2f354a0964ca57374dacc369abac8dbcdd",
        "静态 arm64，POSIX timer UAF → fake cred → ksud late-load（9.213 真机成功字节）",
    )
    val ANDROID = Payload(
        "ek-core-android",
        "payload/ek-core-android",
        "43cc82545dddd7fe10a8549001090aa248cb424e1b28e32e9d4f1164b57c9895",
        "PIE，v4bel 原始 PoC 的 Android 移植（aio spray + oracle）",
    )
    /**
     * 「一种内核分支编一份 payload」：5.10 / 5.15 / 6.1 / 6.6 / 6.12 / 6.18 各一份，
     * 编译时 `-DEXPECT_FAMILY="<前缀>"`，跑在别的分支上会立刻
     * `[guard] payload built for … refusing to run`，不在布局不匹配的内核上写任何东西。
     * 同一分支内各 build 的结构偏移由 device.cfg 提供，不必再按内核分份。
     */

    /**
     * 同族 payload：文件名与资源路径都由版本前缀推出，每次构建只有 sha256 变。
     * 9.145 起每支还带自己的族身份（-DEXTRACTKIT_FAMILY_ID）与标定状态，
     * note 里写清楚「这支的常量是实测的还是推的」，免得日志里 family=generic 看不出归属。
     */

    /**
     * 版本前缀 → 该分支的 payload。tools/build_fam.py 用正则回写这里的 sha256，
     * 所以每个条目必须保持 `"<fam>" to Payloads.fam("<fam>", sha256 = "…")` 的形状。
     */
    /**
     * 9.281：恢复 9.213 的六支分份（整包字节回到 9.213）。
     * 6.6 是唯一真机标定过的分支（PPG-AN00 6.6.118-…-abogki544555896-4k），
     * 其余五支的文本符号地址在运行时退化成 offsets-only，等设备给 device.cfg。
     */
    fun fam(f: String, sha256: String, note: String = ""): Payload = Payload(
        "ek-core-uid0-" + f,
        "payload/fam/ek-core-uid0-" + f,
        sha256,
        note.ifEmpty() {
            if (f == "6.6") "静态 arm64，-DEXPECT_FAMILY=\"$f.\"，本机实测标定（9.213 字节）"
            else "静态 arm64，-DEXPECT_FAMILY=\"$f.\"，offsets-only 待标定（9.213 字节）"
        },
    )

    val PER_FAMILY: Map<String, Payload> = mapOf(
        "5.10" to fam("5.10", sha256 = "5a727664998d5bccbbb3c30699356f98d44c7a42c2e6b540b9cfa70b514c43d7"),
        "5.15" to fam("5.15", sha256 = "61a04bb62205f8fcdc77745f0eb2f6809ecd1683d4468b96099e02dbecc835f3"),
        "6.1" to fam("6.1", sha256 = "4b6022dcdafe29df24d6bb2cece1660f92d64bd9f1db4a57d62c1bb2805a9f59"),
        "6.6" to fam("6.6", sha256 = "29273996225875b603f2ac8e38f6e895eae8062b58e4657ff1396157e9f21444"),
        "6.12" to fam(
            "6.12",
            sha256 = "955f0941406f82654dc63e80603b61b711ebcfe7143c2735671c2e08e9942496",
            note = "9.401: 6.12 支新增一条 profile —— HONOR PPG-AN00 用户提供的 boot.img（6.12.58-android16-6-gdf8d34cadbf7-abogki584560711-4k，未压缩 arm64 Image）。三处调用点用 BL imm26 手工解码（do_timer_create+0xa8 → kmem_cache_alloc_noprof / copy_process+0x13c → kmem_cache_alloc_node_noprof / prepare_creds+0x28 → kmem_cache_alloc_noprof），BTF 与 init_* 符号直接从镜像读；ko-syms 按 release 精确选择，这条 build 有自己的一份。\n\n9.397: 6.12 支接上上游 CVE-2026-98260 的 D 阶段 —— 拿到 uid-0 cred 后在本机进程内 patch 并 finit_module 该 release 的 kernelsu.ko，再跑 root_stage 装 ksud，最后是 KSU root（不再是 9.396 那个只给 uid-0 shell 的链）。ksud/kernelsu.ko 由 payload 自己按 pm path 从管理器 lib/arm64/libksud.so 抽，ko-syms 按 6.12.38 / 6.12.58 内嵌；release 不是这两条 6.12 前缀时自动退回纯 uid-0 shell。这条装载路线只对 6.12 生效，其余五支与 wacom/ghost 一字未动。",
        ),
        "6.18" to fam("6.18", sha256 = "46ae93c2c6ec563138c9ef8750084a0e93d8c13673de5acd96dbbc410bbcac36"),
    )

    /**
     * 9.282：ghost 链（一键root v1.6 / glpreload 同构）的载荷，每支内核一份。
     *
     * 与另外四条链的区别：常量全部按 build 编死（不做运行期探测、不做 offset 回落），
     * 所以只有「有那份内核符号表」的分支才有一份二进制。
     */
    fun ghost(f: String, sha256: String, note: String = ""): Payload = Payload(
        "ek-core-uid0-" + f + "-ghost",
        "payload/ghost/ek-core-uid0-" + f + "-ghost",
        sha256,
        note.ifEmpty() {
            "verbatim original payload bytes: static arm64 ELF, embedded ksud + KMI modules, " +
                "run with zero args from /data/local/tmp; our ksu_stage late-load runs after it"
        },
    )

    /** 已生成的 ghost 载荷（分支 -> Payload）。6.6 待常量落定后补。 */
    /**
     * 9.288：ghost 6.1 换成**原字节**（6,470,288 B 静态 ELF，sha256 pinned）。
     * 以前那份 438,832 B 是我们逆后重写的实现，跑不通；原字节自带 ksud 与 KMI 模块，
     * 所以调用形态也回到原版：cwd=/data/local/tmp、零参数、路径名 glpreload。
     * 跑完后 App 再跑一次我们自己的 assets/stage/ksu_stage.sh（见 ExtractEngine.lateLoadTail）。
     */
    val GHOST: Map<String, Payload> = mapOf(
        "6.1" to ghost(
            "6.1",
            sha256 = "c033080b4dae58d561742d0ad880d63176514f984a44ed1298a9bb2bcad650e5",
            note = "verbatim original bytes (6470288 B, sha256 pinned); embedded ksud late-load; our stage script runs after it",
        ),
    )

    /**
     * 9.298：EK-W1（wacom HID UAF）链的载荷，每支内核一份。
     *
     * 9.328 起换成参考实现（real_cred 模式）：`--mode=real_cred --ksu --profile <json>`，
     * 内核常量全部来自 profile，单进程内完成 finit_module + ksud install + late-load，
     * 不再 exec 一个没有 capability 的 stage 脚本。
     */
    fun wacom(f: String, sha256: String, note: String = ""): Payload = Payload(
        "ek-w1-uid0-" + f,
        "payload/wacom/ek-w1-uid0-" + f,
        sha256,
        note.ifEmpty() {
            "static arm64, wacom HID UAF -> cred patch -> our ksu_stage runs as uid=0 (single pass)"
        },
    )

    val WACOM: Map<String, Payload> = mapOf(
        // 9.402：99491 载荷是数据驱动的（exp.c 只 strcmp(uname release)，uhid/cred/input 偏移
        // 全从 profile 读），上游原本就是针对 6.12.58 写的，6.6 才是适配出来的。所以 6.12 不需要
        // 另编一份二进制：同一份 127,224 B 走这个别名条目，常量由 WacomBuiltin 里
        // 6.12.58-…-gdf8d34cadbf7 那份 profile 提供。
        "6.12" to Payload(
            "ek-w1-uid0-6.6",
            "payload/wacom/ek-w1-uid0-6.6",
            "6530b75fdaa340a8f5b0baf51bc2c1ee9c65fb7a9751c9287f44c06f246c4b22",
            "9.402: same 99491 binary as 6.6 (release + profile decide every offset), now also mapped for family 6.12",
        ),
        // 9.405: 6.1 同样走这一份二进制，profile + ko-syms 由标定按 build 生成。
        // 上游的 UAF 路径是 uhid/timer 通用的，逐 build 的只有结构偏移和符号地址。
        "6.1" to Payload(
            "ek-w1-uid0-6.6",
            "payload/wacom/ek-w1-uid0-6.6",
            "6530b75fdaa340a8f5b0baf51bc2c1ee9c65fb7a9751c9287f44c06f246c4b22",
            "9.425: same upstream 99491 binary; calibrate a 6.1 boot.img first so the profile and ko-syms table exist",
        ),
        "6.6" to wacom(
            "6.6",
            sha256 = "6530b75fdaa340a8f5b0baf51bc2c1ee9c65fb7a9751c9287f44c06f246c4b22",
            note = "9.443: exp.c is byte-identical to upstream again. Everything I added between 9.440 and 9.442 is gone: the VLOG silencing, the cred-blob uid..fsgid rewrite with the forced full capability set in no-tracefs, the in-process loader call there (upstream forks itself with ksu-load, so that is back), and the trimmed K-report handling. The only remaining delta from upstream is the ko-syms precheck, dropped on purpose so any calibrated kernel family can run. The manager-installs-ksud layer lives in ksu_boot.c and is unchanged since 9.439. 9.444 puts back the one thing the upstream rollback dropped by accident: the 9.393 tracefs outq disarm before the loader exec (NULL outq[0]/outq[1], otherwise uhid_char_release kfree()s the reclaimed 2k slot and the phone panics a second after ksu ready). real_cred and no-tracefs already had it."
        ),
    )

    /**
     * 9.408：99491 不再按内核家族设门。
     *
     * 载荷本身是数据驱动的 —— exp.c 只比 uname release 与 profile 的 release，
     * 结构偏移全来自 profile、模块补丁地址全来自 ko-syms 表。所以只要这台机器
     * 标定过（profile 存在），任何内核都能在主页直接跑这条链。跑不跑得通
     * （uid=0 / 不 panic）由真机决定，但不再被「家族不在名单」拦下。
     */
    fun wacomFor(family: String?): Payload? = WACOM[family ?: ""] ?: WACOM["6.6"]

    val CALIB = Payload(
        "calib",
        "payload/ek-calib",
        "1dc7f286bbde3059d7805b7e94785467998777d42ce7675b1166013f977b62a7",
        "只读标定 census（9.213 字节）",
    )

    val PERFPROBE = Payload(
        "perfprobe",
        "payload/honor/perfprobe",
        "d3d3a32a5996acc2b950af88a4594c5987d421f52653a6786fb6a6aa70ef3a3e",
        "只读探针：tgt-ran / tgt-check 两个标记，9.213 字节",
    )
}

/**
 * 一个可执行的提取动作：跑哪个载荷、带什么参数、什么标志算成功。
 *
 * steps 非空时表示“一键链”，按顺序跑完每一步。
 */
data class Mode(
    val id: String,
    val label: String,
    val target: Payload,
    val args: String = "",
    val successMarkers: List<String> = emptyList(),
    val timeoutSec: Long = 0L,
    val persists: Boolean = false,
    val note: String = "",
    val steps: List<String> = emptyList(),
) {
}

object Modes {
    val ALL: List<Mode> = listOf(
        Mode(
            "leak_uid0",
            "② 信息泄漏 · uid0 leak",
            Payloads.UID0,
            args = "leak",
            successMarkers = listOf(
                "leak-only run complete; 9.345 removes the three diagnostics that were quietly spending blind fires in the grab stage (the EV_ABS selftest, the per-round anchor probe and the control read all go through pc_write, so each cost a full spray round): the grab loop is upstream again and the only added output is a stderr copy of the got/want line",
            ),
            timeoutSec = 180,
            note = "9.374 rebuilds the payload from the published sources verbatim (exp.c, ko_patch.c, profile.h untouched) and replaces exactly one step, the module bootstrap: ksu_load_module_at no longer runs debug extract-binary + ko_patch + finit_module on a .ko we patched ourselves, it stages the ksud that ships inside the selected manager package and runs late-load --post-magica --package-name, so the module is loaded by the manager own loader and no ko offsets or slide reach it. The staged ksud comes from the profile lib path, or from the largest *.so in lib/arm64 when the manager renamed it, and a failed .ko extract no longer aborts the load. 129,408 B stripped.",
        ),
        Mode(
            "selftest_uid0",
            "② 写原语自测 · uid0 selftest",
            Payloads.UID0,
            args = "selftest",
            successMarkers = listOf("SELFTEST"),
            timeoutSec = 240,
            note = "把 8 字节零写打在自己进程的页上，验证原语是否成立（不会动别的进程）。",
        ),
        Mode(
            "extract_uid0",
            "③ 提取 root · uid0 fake → KernelSU",
            Payloads.UID0,
            args = "fake",
            successMarkers = listOf(Verdict.MARKER_CHILD_UID0, "[+] ksu ready", "KSU_LOADED"),
            timeoutSec = 420,
            persists = true,
            note = "fake cred + 补 SELinux + ksud late-load。成功后 exploit 进程会驻留，别 kill。",
        ),
        Mode(
            "extract_ekcore",
            "③ 提取 root · CVE-2026-98260 主链（aio spray）",
            Payloads.ANDROID,
            successMarkers = listOf("uid=0", "ROOT"),
            timeoutSec = 600,
            persists = true,
            note = "v4bel 路线的 Android 版：aio 环喷雾 + oracle 计时，成功后起 root shell。",
        ),
        Mode(
            "chain_uid0",
            "★ 一键：提取（uid0）",
            Payloads.UID0,
            timeoutSec = 0,
            persists = true,
            note = "9.146 起不再单跑那一步确认：payload 自己会在写之前做完同样的检查，多跑一遍只是白等 90 秒。",
            steps = listOf("extract_uid0"),
        ),
        Mode(
            "chain_ekcore",
            "★ 一键：提取（CVE-2026-98260）",
            Payloads.ANDROID,
            timeoutSec = 0,
            persists = true,
            note = "9.156 起不再预检：payload 自己写之前会做同样的检查，多跑一遍只会白等，还会把采样偶然失败的链判死。",
            steps = listOf("extract_ekcore"),
        ),
    )

    fun byId(id: String): Mode = ALL.first { it.id == id }
}