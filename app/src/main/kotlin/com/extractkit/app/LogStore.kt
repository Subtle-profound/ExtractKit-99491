package com.extractkit.app

import android.content.Context
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 落盘日志。设备 panic/重启后 adb 会一起断，只有写进文件的日志能回看死在哪一步
 * —— 这是两个上游仓库都强调过的第一条纪律。
 */
class LogStore(private val ctx: Context) {

    private val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.ROOT).format(Date())
    private val timeFmt = SimpleDateFormat("HH:mm:ss.SSS", Locale.ROOT)

    private val dir: File by lazy {
        val base = ctx.getExternalFilesDir(null) ?: ctx.filesDir
        File(base, "logs").apply { mkdirs() }
    }

    val file: File by lazy {
        val f = File(dir, "extract-$stamp.log")
        prune(keep = 10, mine = f.name)
        f
    }

    /** Keep the newest `keep` logs (never the one this session writes). */
    private fun prune(keep: Int = 10, mine: String? = null) {
        runCatching {
            val all = dir.listFiles { f -> f.isFile && f.name.startsWith("extract-") && f.name.endsWith(".log") }
                ?.sortedByDescending { it.lastModified() }
                ?: return
            if (all.size <= keep) return
            all.filter { it.name != mine }.drop(keep - 1).forEach { runCatching { it.delete() } }
        }
    }

    @Synchronized
    fun append(line: String) {
        runCatching {
            file.appendText("[${timeFmt.format(Date())}] $line\n")
        }
    }

    fun read(): String = runCatching { file.readText() }.getOrDefault("")

    /** 所有历史日志，最新的在前（本次会话的那份永远排第一）。 */
    fun history(): List<File> {
        val all = dir.listFiles { f -> f.isFile && f.name.startsWith("extract-") && f.name.endsWith(".log") }
            ?.sortedByDescending { it.lastModified() }
            ?.toMutableList()
            ?: mutableListOf()
        // 本次会话的日志只有在真的写过东西之后才存在；没写过就别塞一个空文件占住第 1 条，
        // 否则"上一次提权的日志"会被这个空壳顶掉，日志面板看起来是空的。
        if (all.none { it.absolutePath == file.absolutePath } && (file.exists() || all.isEmpty())) {
            all.add(0, file)
        }
        return all
    }

    /**
     * 只读文件末尾 maxBytes：日志可能是几百 KB，整份读进来会把主线程拖死。
     * 从第一个换行之后开始返回，保证不会切出半行。
     */
    fun tailFrom(f: File, maxBytes: Int = 262_144): String = runCatching {
        val len = f.length()
        val from = if (len <= maxBytes) 0L else len - maxBytes
        java.io.RandomAccessFile(f, "r").use { raf ->
            raf.seek(from)
            val buf = ByteArray((len - from).toInt())
            raf.readFully(buf)
            val text = String(buf, Charsets.UTF_8)
            if (from == 0L) text else text.substringAfter('\n', text)
        }
    }.getOrDefault("")

}
