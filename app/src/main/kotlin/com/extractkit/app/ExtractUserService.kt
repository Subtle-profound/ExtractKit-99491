package com.extractkit.app

import android.content.Context
import android.os.ParcelFileDescriptor
import android.system.Os
import androidx.annotation.Keep
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.io.RandomAccessFile

/**
 * 运行在 Shizuku 提供的 shell 上下文里（uid 2000，`u:r:shell:s0`）。
 *
 * 这里只做三件事：起进程、把输出搬回来、把文件落盘。
 * 利用逻辑全部在被执行的 payload 里，本类不碰内核。
 */
@Keep
class ExtractUserService(@Suppress("UNUSED_PARAMETER") context: Context) : IExtractService.Stub() {

    private companion object {
        const val MAX_CAPTURE = 512 * 1024
        const val WORK_DIR = "/data/local/tmp/extract-kit"
        const val CHUNK = 8192

        /** 9.293：cwd 回退顺序。WORK_DIR 被 root 侧改成 root-only / 换标签后要能降级。 */
        val CWD_CANDIDATES = listOf(WORK_DIR, "/data/local/tmp", "/")

        /** 9.293：sh 回退顺序（有的机器上没有 sh 这个短名）。 */
        val SH_CANDIDATES = listOf("/system/bin/sh", "sh")
    }

    private var sink: FileOutputStream? = null
    private var sinkPath: String? = null

    /** 9.293：上一次真正 start() 成功的组合，下次直接复用，省掉 6 次试错。 */
    @Volatile private var goodCwd: String? = null
    @Volatile private var goodSh: String? = null

    /** 9.293：最近一次全组合失败的原因（成功即清空），供 diag() 回读。 */
    @Volatile private var lastSpawnError: String? = null

    override fun execStream(command: String, out: ParcelFileDescriptor): Int {
        var process: Process? = null
        try {
            process = newProcess(command)
            val source: InputStream = process.inputStream
            ParcelFileDescriptor.AutoCloseOutputStream(out).use { target ->
                val buf = ByteArray(CHUNK)
                while (true) {
                    val n = source.read(buf)
                    if (n <= 0) break
                    target.write(buf, 0, n)
                    target.flush()
                }
            }
            return process.waitFor()
        } catch (t: Throwable) {
            // 客户端提前关掉读端会在这里抛 IOException：收掉进程，别留孤儿
            runCatching { process?.destroy() }
            return -1
        }
    }

    override fun exec(command: String): String {
        var process: Process? = null
        return try {
            process = newProcess(command)
            val buffer = ByteArrayOutputStream()
            val buf = ByteArray(CHUNK)
            val input: InputStream = process.inputStream
            while (true) {
                val n = input.read(buf)
                if (n <= 0) break
                if (buffer.size() + n > MAX_CAPTURE) {
                    buffer.write(buf, 0, MAX_CAPTURE - buffer.size())
                    break
                }
                buffer.write(buf, 0, n)
            }
            val code = process.waitFor()
            "$code\n" + buffer.toString(Charsets.UTF_8.name())
        } catch (t: Throwable) {
            runCatching { process?.destroy() }
            "-1\n$t"
        }
    }

    override fun fileOpen(path: String) {
        runCatching { File(path).parentFile?.mkdirs() }
        runCatching { sink?.close() }
        sink = FileOutputStream(path, false)
        sinkPath = path
    }

    override fun fileWrite(chunk: ByteArray) {
        val out = sink ?: throw IllegalStateException("fileOpen() 还没调用")
        out.write(chunk)
        out.flush()
    }

    override fun fileClose(mode: Int) {
        val out = sink
        runCatching { out?.fd?.sync() }
        runCatching { out?.close() }
        sink = null
        val path = sinkPath ?: return
        sinkPath = null
        runCatching { Os.chmod(path, mode) }
    }

    /**
     * 9.294：无状态写一块。truncate=true 时以覆盖方式打开（第一块），否则追加。
     * mode >= 0 时在这块写完后 chmod（由客户端在最后一块传入）。
     */
    override fun filePut(path: String, chunk: ByteArray, truncate: Boolean, mode: Int): Long {
        runCatching { File(path).parentFile?.mkdirs() }
        FileOutputStream(path, !truncate).use { out ->
            out.write(chunk)
            out.flush()
            runCatching { out.fd.sync() }
        }
        if (mode >= 0) runCatching { Os.chmod(path, mode) }
        // 9.295：把设备上真实的字节数回给客户端。9.294 只信 binder 不抛异常就当好，
        // 结果 9.294 真机出现「pushFile 返回 0 但 .new 文件不存在」（deploy 的 mv 报
        // No such file or directory）。写得成没写成，只有服务端自己 stat 才算数。
        return runCatching { File(path).length() }.getOrDefault(-1L)
    }

    override fun readAt(path: String, offset: Long, length: Int): ByteArray {
        if (length <= 0) return ByteArray(0)
        return try {
            RandomAccessFile(path, "r").use { file ->
                val size = file.length()
                if (offset >= size) return ByteArray(0)
                val want = minOf(length.toLong(), size - offset).toInt()
                val buffer = ByteArray(want)
                file.seek(offset)
                var read = 0
                while (read < want) {
                    val n = file.read(buffer, read, want - read)
                    if (n <= 0) break
                    read += n
                }
                if (read == want) buffer else buffer.copyOf(read)
            }
        } catch (t: Throwable) {
            ByteArray(0)
        }
    }

    override fun destroy() {
        runCatching { sink?.close() }
        runCatching { System.exit(0) }
    }

    // ------------------------------------------------------------------ 内部

    override fun diag(): String {
        val uid = runCatching { android.os.Process.myUid() }.getOrDefault(-1)
        val fds = runCatching { File("/proc/self/fd").list()?.size ?: -1 }.getOrDefault(-1)
        fun canExec(path: String) = runCatching {
            File(path).let { it.isDirectory && it.canExecute() }
        }.getOrDefault(false)
        return "uid=" + uid + ";cwd=" + (goodCwd ?: "-") + ";sh=" + (goodSh ?: "-") +
            ";fds=" + fds +
            ";workdir_exec=" + (if (canExec(WORK_DIR)) 1 else 0) +
            ";tmp_exec=" + (if (canExec("/data/local/tmp")) 1 else 0) +
            ";err=" + (lastSpawnError ?: "-").replace('\n', ' ')
    }

    /**
     * 9.293：以前把 cwd 写死成 WORK_DIR。那个目录被 root 侧跑过之后，uid=2000 可能
     * 连 chdir 都做不到，于是 **每条命令** 都抛 java.io.IOException，probe() 一个字都
     * 拿不回来，整条链被误报成 NO_TRACEFS。这里改成候选回退：先试上次成功的组合，
     * 再逐级降级 cwd 与 sh；全部失败才抛，并把 6 条原因拼进异常文本。
     */
    private fun newProcess(command: String): Process {
        val cwds = (listOfNotNull(goodCwd) + CWD_CANDIDATES).distinct()
        val shells = (listOfNotNull(goodSh) + SH_CANDIDATES).distinct()
        val failures = ArrayList<String>(cwds.size * shells.size)
        for (cwd in cwds) {
            for (shell in shells) {
                try {
                    val process = startOnce(shell, cwd, command)
                    goodCwd = cwd
                    goodSh = shell
                    lastSpawnError = null
                    return process
                } catch (t: Throwable) {
                    failures += cwd + "/" + shell + ": " + t.javaClass.simpleName + ": " + t.message
                }
            }
        }
        lastSpawnError = failures.joinToString(" | ")
        throw java.io.IOException("cannot fork sh (all " + cwds.size * shells.size + " combinations failed): " + lastSpawnError)
    }

    private fun startOnce(shell: String, cwd: String, command: String): Process {
        val dir = File(cwd)
        if (cwd == WORK_DIR) runCatching { dir.mkdirs() }
        val usable = dir.isDirectory && dir.canRead()
        val builder = ProcessBuilder(shell, "-c", command)
        if (usable) runCatching { builder.directory(dir) }
        builder.redirectErrorStream(true)
        val env = builder.environment()
        env["PATH"] = "/system/bin:/system/xbin:/vendor/bin:" + WORK_DIR
        env["HOME"] = if (usable) cwd else WORK_DIR
        return builder.start()
    }
}
