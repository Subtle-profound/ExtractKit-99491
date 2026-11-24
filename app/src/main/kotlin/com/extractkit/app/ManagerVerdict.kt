package com.extractkit.app

/**
 * 管理器 appid 注册状态的判定（9.290 抽出来的纯函数，便于单测）。
 *
 * 判据优先级：
 * 1. 内核模块参数读回（/sys/module/kernelsu/parameters 里的 package_name）——唯一不靠我们自证的证据；
 * 2. 我们脚本成功后写的 marker（$WORK_DIR/mgr_registered，内容 pkg:uid）；
 * 3. 脚本退出码 5 = 所选包内确实没有 ksud（XEC 这类只读内核状态的管理器）；
 * 4. “kernelsu 模块在”只能算 unverified，不能算注册成功——9.289 之前的假成功就是这么来的。
 */
object ManagerVerdict {

    fun of(mgr: String, reg: String, params: List<String>, after: Int, exit: String?): String {
        val keyed = params.firstOrNull { l ->
            val k = l.substringBefore('=')
            k == "package_name" || k == "manager_package_name" || k == "manager_appid"
        }
        val kernelPkg = keyed?.substringAfter('=')?.trim().orEmpty()
        val regPkg = reg.substringBefore(':').trim()
        val uid = reg.substringAfter(':', "").trim()
        return when {
            kernelPkg.isNotEmpty() && kernelPkg != "0" && (kernelPkg == mgr || kernelPkg == regPkg) ->
                "registered(" + kernelPkg + (if (uid.isNotEmpty()) ":" + uid else "") + ")"
            kernelPkg.isNotEmpty() && kernelPkg != "0" -> "registered(" + kernelPkg + ", NOT " + mgr + ")"
            regPkg.isNotEmpty() -> "registered-unverified(" + reg + ")"
            exit?.trim()?.removePrefix("LATE_EXIT=") == "5" -> "no-ksud(" + mgr + ")"
            after > 0 -> "unverified"
            else -> "FAILED"
        }
    }
}
