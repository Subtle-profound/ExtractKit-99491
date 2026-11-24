package com.extractkit.app

/**
 * 内核 release -> payload 分支（"5.10" / "5.15" / "6.1" / "6.6" / "6.12" / "6.18"）的映射。
 *
 * 为什么单独一个文件：分支名同时决定
 *  1) assets/payload/fam/ek-core-uid0-<fam> 用哪一份二进制；
 *  2) -DEXPECT_FAMILY="<fam>." 的编译期闸门（跑错分支会自己拒绝）；
 *  3) 界面上「这台机器属于哪一支」的展示。
 *
 * 只取 主.次 两段，补丁号/构建串不参与匹配 —— 5.10.252-android12-9-g... 截成
 * 5.10.252 就永远匹配不到 5.10，这个坑 9.66 踩过。
 */
object ReleaseMatrix {

    /** 编译期有分支 payload 的六支（顺序即界面上从旧到新）。 */
    val FAMILIES: List<String> = listOf("5.10", "5.15", "6.1", "6.6", "6.12", "6.18")

    /**
     * 唯一有真镜像标定过的分支：6.6.118-android15-8-g554929766a0d-…-4k（PPG-AN00）。
     * 其余五支只有 family_defaults.h 里按结构布局推出来的默认 —— 6.6 的 kallsyms
     * 地址对它们是错的，所以那些分支编出来的 payload 把文本符号地址全置 0，
     * 运行时自动退 offsets-only，直到设备上给了 device.cfg。
     */
    const val CALIBRATED: String = "6.6"

    /** 这一支的常量是不是实测标定过的（不是推出来的）。 */
    fun isCalibrated(family: String?): Boolean = family == CALIBRATED

    /**
     * 冻结但暂停自动选用的分支。
     *
     * 9.184 曾把 6.12 放进来：那一支的二进制是 9.104 基线原字节，在 6.12.x 上跑到
     * 利用阶段会 panic。9.185（用户 m07675「出」）把 6.12 从 build_fam.py 的
     * PINNED_9104 里移了出来，用当前主源重编（带外部 page_offset 回落），字节
     * 已经不再是冻结版，所以这里不再暂停任何分支。机制保留：以后要冻哪一支，
     * 往这个集合里加即可。
     */
    val HOLD: Set<String> = emptySet()

    /** 该分支是否处于「冻结、暂停自动选用」状态。 */
    fun isHeld(family: String?): Boolean = family != null && HOLD.contains(family)

    private val VERSION = Regex("""(\d{1,3})\.(\d{1,3})""")

    /**
     * release 里能解析出「主.次」两段数字就返回它，否则 null。
     *
     * uname -r 的形式是 <版本>-<android 分支>-<提交/CI 号>，版本号在第一位；
     * 前面带杂字符（例如 "Linux version "）也不受影响。
     */
    fun majorMinor(release: String?): String? {
        val text = release?.trim().orEmpty()
        if (text.isEmpty()) return null
        val m = VERSION.find(text) ?: return null
        return m.groupValues[1] + "." + m.groupValues[2]
    }

    /**
     * 命中内置六支时返回分支名；没命中返回 null（调用方回落到原来的字面版 payload）。
     *
     * 6.6.118-android15-8-... 与 6.1.138-android14-11-... 都按主.次匹配，与具体
     * build 无关 —— 同一分支内各 build 的结构偏移由 device.cfg 提供。
     */
    fun familyOf(release: String?): String? {
        val mm = majorMinor(release) ?: return null
        return FAMILIES.firstOrNull { it == mm }
    }

    /** 分支 payload；该分支没有编出来的二进制时返回 null。 */
    fun payloadOf(release: String?): Payload? {
        val fam = familyOf(release) ?: return null
        return Payloads.PER_FAMILY[fam]
    }

    /** 给日志用的一句话：命中哪支 / 为什么没命中。 */
    fun describe(release: String?): String {
        val mm = majorMinor(release)
        if (mm == null) return "cannot parse major.minor from release (" + (release ?: "empty") + ")"
        val fam = familyOf(release)
        if (fam == null) {
            return "kernel " + mm + " outside family matrix (built: " +
                FAMILIES.joinToString("/") + "); falling back to literal payload"
        }
        if (isHeld(fam)) {
            return "kernel " + mm + " -> family " + fam +
                " (9.104 frozen bytes; panics on 6.12.x, auto-selection paused)"
        }
        return "kernel " + mm + " -> family " + fam +
            if (fam == CALIBRATED) " (calibrated)"
            else " (uncalibrated: falls back to offsets-only without device.cfg)"
    }
}
