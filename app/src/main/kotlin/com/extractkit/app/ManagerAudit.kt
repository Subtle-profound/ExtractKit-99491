package com.extractkit.app

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * 管理器自检：对**每一个**已安装的管理器，跑一遍 ksu_stage.sh 的解析分支
 * （EXTRACTKIT_DRYRUN=1，只解析、不覆盖任何文件），把「会用哪个 ksud、
 * 是不是借用别家的」摊开给用户看。
 *
 * 为什么要这个：包名送错/ksud 借错品牌都会表现成「提权成功但管理器没越狱」，
 * 而那种现象很难从日志里一眼看出根因。自检表把判定提前暴露。
 */
object ManagerAudit {

    data class Row(
        val pkg: String,
        val label: String,
        val src: String,
        val owner: String,
        val cross: Boolean,
        val why: String,
    ) {
        /** shell 域读不了 /data/app，这一项没法判断（不是"缺 ksud"） */
        val noPerm: Boolean get() = why == "noperm"

        /** 一行结论：自我 / 借用 / 缺失 / 无权限 */
        val verdict: String
            get() = when {
                noPerm -> "需 root 才能读"
                src.isBlank() -> "缺 ksud"
                !cross -> "自我"
                owner.isBlank() -> "借用（未知来源）"
                else -> "借用 $owner"
            }

        val isSelf: Boolean get() = !noPerm && src.isNotBlank() && !cross
    }

    const val DIR = "/data/local/tmp/extract-kit"

    /** 下发后的脚本路径；9.199 起主链把它作为 EXTRACTKIT_STAGE 传给 payload。 */
    const val SCRIPT = "$DIR/ksu_stage.sh"
    private const val ASSET = "stage/ksu_stage.sh"

    /** 把脚本推上去（每次覆盖，脚本很小） */
    suspend fun deploy(ctx: Context): Boolean = withContext(Dispatchers.IO) {
        val bytes = runCatching { ctx.assets.open(ASSET).use { it.readBytes() } }.getOrNull()
            ?: return@withContext false
        Shell.exec("mkdir -p $DIR")
        if (Shell.pushFile(SCRIPT, bytes, executable = true).first != 0) {
            android.util.Log.w("ExtractKit", "stage deploy: push failed")
            return@withContext false
        }
        // 9.272：推上去之后必须核对设备上的字节数。曾经出现过设备上留着旧脚本
        // （16,970 B，9.222 时代），而 App 以为下发成功，于是 payload 跑的是一份
        // 没有「已加载就跳过」「自己 insmod」这两段的旧梯子，表现为 late-load 失败。
        val onDev = Shell.exec("wc -c < $SCRIPT").second.trim().takeWhile { it.isDigit() }
        val want = bytes.size.toString()
        android.util.Log.i("ExtractKit", "stage deploy: want=$want got=$onDev")
        onDev == want
    }

    /** 9.292: the environment block the log carries when a manager is unusable. */
    fun envInfo(): List<String> = listOf(
        "stage=" + SCRIPT,
        "dir=" + DIR,
    )
}
