package com.extractkit.app

import android.content.ComponentName
import android.content.Context
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.ParcelFileDescriptor
import rikka.shizuku.Shizuku
import java.io.InputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * shell 上下文访问层。
 *
 * Shizuku 的 `newProcess()` 是 private 的，普通 App 只能通过 **UserService** 拿到
 * 以 shell(uid 2000) 身份运行的进程，所以这里的正路是：
 *
 *   Shizuku.bindUserService()  →  ExtractUserService(跑在 shell 上下文)
 *        →  exec / execStream / pushFile
 *
 * 没有 Shizuku 授权时所有方法都返回失败，不会退回本地进程 —— 本机 uid 打不动内核。
 */
object Shell {

    const val PERMISSION_REQUEST = 4101

    @Volatile
    private var service: IExtractService? = null

    @Volatile
    private var boundConnection: ServiceConnection? = null

    @Volatile
    private var boundArgs: Shizuku.UserServiceArgs? = null

    @Volatile
    private var lastError: String? = null

    /** 9.286: reap 自己的结论单独记一份。lastError 会被 bind 失败覆盖，窄窗口诊断会被吃掉。 */
    @Volatile
    private var reapNote: String? = null

    /** 记住最近一次 connect 的 Context，binder 失效时用来原地重连。 */
    @Volatile
    private var appContext: Context? = null

    /** connect 串行化：两条路径同时 bind 会起两个 :shell，互相把对方顶掉。 */
    private val gate = Any()

    /** 正在 bindUserService 的窗口期：这期间绝不能 reap（会 kill 掉自己刚 fork 的 :shell）。 */
    @Volatile
    private var binding = false

    /** 每个进程生命周期只打扫一次遗留进程，避免每次重绑都去 su 一趟。 */
    @Volatile
    private var reaped = false

    fun alive(): Boolean = try {
        Shizuku.pingBinder()
    } catch (t: Throwable) {
        false
    }

    fun granted(): Boolean = try {
        alive() && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
    } catch (t: Throwable) {
        false
    }

    fun requestPermission() {
        runCatching { if (alive()) Shizuku.requestPermission(PERMISSION_REQUEST) }
    }

    fun providerUid(): Int = try {
        if (alive()) Shizuku.getUid() else -1
    } catch (t: Throwable) {
        -1
    }

    fun connected(): Boolean = service != null && isAlive()

    private fun isAlive(): Boolean = try {
        service?.asBinder()?.isBinderAlive == true
    } catch (t: Throwable) {
        false
    }

    fun error(): String? = lastError

    /**
     * 绑定 UserService。**必须在非主线程调用**：ServiceConnection 回调走主线程，
     * 在主线程上等 latch 会自己把自己锁死。
     *
     * 9.286：HONOR 上卡在「connect Shizuku UserService」的两个真实原因都堵住了：
     *  1) 重绑前那次 reapStaleUserServices() 按进程名 pgrep，会把 bindUserService
     *     刚 fork 出来的我们自己的 :shell 一起 kill -9 —— binder 永不回调、超时、
     *     再重绑再 kill，看着就是永久卡住。现在只杀「绑定开始之前」的快照 pid；
     *  2) 三枪之间一句日志都没有，界面像死机。现在每枪都报 binder/版本/超时。
     * 另外 connect 串行化，避免两条路径同时 bind 起两个 :shell 互相顶掉。
     */
    fun connect(ctx: Context, timeoutMs: Long = 0, onProgress: ((String) -> Unit)? = null): Boolean =
        synchronized(gate) {
            val started = System.currentTimeMillis()
            val budget = if (timeoutMs > 0) listOf(timeoutMs) else listOf(6_000L, 12_000L, 20_000L)
            if (!reaped) {
                reaped = true
                // 9.286: reap 必须严格跑在第一枪 bind 之前。否则它取 pid 快照时我们自己的
                // :shell 可能已经在起来了，就又绕回「自己杀自己」那条路。
                runCatching { reapStaleUserServices()?.join(3_000) }
            }
            budget.forEachIndexed { i, ms ->
                val ver = runCatching { Shizuku.getVersion() }.getOrDefault(-1)
                onProgress?.invoke(
                    "· shizuku: binder=" + (if (alive()) "ok" else "down") +
                        " version=v" + ver + " providerUid=" + providerUid() +
                        " attempt=" + (i + 1) + "/" + budget.size + " timeout=" + (ms / 1000) + "s",
                )
                if (connectOnce(ctx, ms)) {
                    onProgress?.invoke("· shizuku: UserService connected (attempt " + (i + 1) + ")")
                    return@synchronized true
                }
                val why = lastError ?: "unknown"
                onProgress?.invoke("! shizuku: attempt " + (i + 1) + " failed: " + why)
                if (i + 1 < budget.size) runCatching { Thread.sleep(400) }
            }
            // 9.286: one summary line, so the phone-side log answers "how long, which side, why".
            onProgress?.invoke(
                "! shizuku: all " + budget.size + " attempts failed in " +
                    ((System.currentTimeMillis() - started) / 1000) + "s" +
                    " (binder=" + (if (alive()) "ok" else "down") +
                    " version=v" + runCatching { Shizuku.getVersion() }.getOrDefault(-1) +
                    " providerUid=" + providerUid() +
                    "; last: " + (lastError ?: "unknown") +
                    "; reap: " + (reapNote ?: "none") + ")",
            )
            false
        }

    private fun connectOnce(ctx: Context, timeoutMs: Long): Boolean {
        if (service != null && isAlive()) return true
        // 还拿着旧连接但已经不通了：先解绑，避免又起一个新进程
        if (boundConnection != null) disconnect()
        if (!granted()) {
            // 分清「没运行」和「没授权」：这两种情况用户要做的事完全不同。
            val up = runCatching { Shizuku.pingBinder() }.getOrDefault(false)
            lastError = if (up) "Shizuku unauthorized (grant ExtractKit access in Shizuku)"
                       else "Shizuku not running (start it via wireless debugging first)"
            return false
        }
        lastError = null

        val app = ctx.applicationContext
        appContext = app
        val args = Shizuku.UserServiceArgs(
            ComponentName(app.packageName, ExtractUserService::class.java.name),
        )
            .daemon(false)
            .processNameSuffix("shell")
            .debuggable(false)
            .version(BuildConfig.VERSION_CODE)

        val latch = CountDownLatch(1)
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
                service = runCatching { IExtractService.Stub.asInterface(binder) }.getOrNull()
                if (service == null) lastError = "UserService binder cast failed"
                latch.countDown()
            }

            override fun onServiceDisconnected(name: ComponentName?) {
                service = null
                lastError = "UserService disconnected"
                latch.countDown()
            }
        }
        boundConnection = connection

        binding = true
        try {
            Handler(Looper.getMainLooper()).post {
                runCatching { Shizuku.bindUserService(args, connection) }
                    .onFailure {
                        lastError = "bind failed: " + it
                        latch.countDown()
                    }
            }

            val done = runCatching { latch.await(timeoutMs, TimeUnit.MILLISECONDS) }.getOrDefault(false)
            if (!done || service == null) {
                if (lastError == null)
                    lastError = "UserService did not start (" + (timeoutMs / 1000) + "s timeout): check Shizuku is running, this app is authorized, background start is allowed" +
                        " (Shizuku v" + runCatching { Shizuku.getVersion() }.getOrDefault(-1) + ", providerUid=" + providerUid() + ")"
                runCatching { Shizuku.unbindUserService(args, connection, true) }
                boundConnection = null
                boundArgs = null
                return false
            }
        } finally {
            binding = false
        }
        boundArgs = args
        return true
    }

    /**
     * 清掉上一次会话遗留的 UserService 进程。
     *
     * Shizuku 的 UserService 是**独立进程**（com.extractkit.app:shell）。App 被
     * 强停/被杀时 binder 直接断，Shizuku 不会回收那个进程，于是它变成 ppid=1 的
     * 孤儿，每个约 130 MB。
     *
     * 9.286：只杀「调用这一刻之前就存在」的 pid 快照，且真正 kill 之前再确认一次
     * 我们没在 bind 窗口里 —— 旧实现按名字 pgrep，会把刚 fork 出来的自己杀了。
     */
    private fun reapStaleUserServices(): Thread? {
        val job = Thread {
            runCatching {
                val pids = staleShellPids()
                if (pids.isEmpty()) return@runCatching
                if (service != null || binding) {
                    reapNote = "reap skipped: our own UserService is up"
                    return@runCatching
                }
                val cmd = pids.joinToString(" ") { "kill -9 " + it + " 2>/dev/null;" }
                val p = ProcessBuilder("su", "-c", cmd).redirectErrorStream(true).start()
                p.waitFor(4, TimeUnit.SECONDS)
            }
        }
        job.isDaemon = true
        job.name = "extractkit-reap"
        job.start()
        return job
    }

    /** su 现在能不能用。用 `su -c true` 探：非零退出、超时、抛异常一律算不可用。 */
    private fun suAvailable(): Boolean = try {
        val p = ProcessBuilder("su", "-c", "true").redirectErrorStream(true).start()
        if (!p.waitFor(2, TimeUnit.SECONDS)) {
            p.destroy()
            false
        } else {
            p.exitValue() == 0
        }
    } catch (t: Throwable) {
        false
    }

    /** 上一会话遗留的 :shell pid 列表；有 payload 进程活着时返回空表（不打扫）。 */
    private fun staleShellPids(): List<Int> {
        // 9.286: 设备上还没有 su 的时候，下面每条 ProcessBuilder("su", ...) 都直接抛异常，
        // 被 runCatching 吞掉后日志一句不剩 —— 看起来像「打扫过了」，其实什么都没做。
        // 先探一次 su，把这两种情况在日志里分开。
        if (!suAvailable()) {
            reapNote = "reap skipped: no su yet"
            return emptyList()
        }
        val guard = ProcessBuilder(
            "su", "-c", "pgrep -f 'ek-core-uid0' | head -n 1",
        ).redirectErrorStream(true).start()
        if (!guard.waitFor(2, TimeUnit.SECONDS)) {
            guard.destroy()
            return emptyList()
        }
        val alive = guard.inputStream.bufferedReader().use { it.readText() }.trim()
        if (alive.isNotEmpty()) {
            reapNote = "reap skipped: payload pid=" + alive + " alive (isolate)"
            return emptyList()
        }
        val q = ProcessBuilder(
            "su", "-c", "pgrep -f 'com.extractkit.app:shell'",
        ).redirectErrorStream(true).start()
        if (!q.waitFor(2, TimeUnit.SECONDS)) {
            q.destroy()
            return emptyList()
        }
        return q.inputStream.bufferedReader().use { it.readText() }
            .lineSequence().mapNotNull { it.trim().toIntOrNull() }.toList()
    }

    fun disconnect() {
        val args = boundArgs
        val conn = boundConnection
        if (args != null && conn != null) {
            runCatching { Shizuku.unbindUserService(args, conn, false) }
        }
        service = null
        boundConnection = null
        boundArgs = null
    }

    // -------------------------------------------------------------- 一次性执行

    /** 9.293：最近一次 exec/pushFile 拿到的完整异常文本（不再 take(8) 截断，供 SHELL_* 分类）。 */
    @Volatile
    private var lastExecError: String? = null

    fun lastExecErrorText(): String? = lastExecError

    /** 9.293: the UserService reports its own cwd/sh/fd state when the shell channel is unusable. */
    fun diag(): String {
        val svc = service ?: return "not connected (" + (lastError ?: "no service") + ")"
        return try {
            svc.diag()
        } catch (t: Throwable) {
            "diag failed: " + t
        }
    }

    /** 9.295：上一次 pushFile 的分块/落盘实数，日志里打出来才知道写到哪一步断的。 */
    @Volatile
    var lastPushInfo: String? = null
        private set

    fun exec(command: String): Pair<Int, String> {
        // binder 失效（管理器重启 / 进程被收）时先原地重连一次。
        // 以前直接返回 -1，"su -c id" 会被误判成「没有 root」。
        var svc = service
        if (svc == null || !isAlive()) {
            val ctx = appContext
            if (ctx != null) {
                runCatching { connect(ctx, 5_000) }
                svc = service
            }
        }
        if (svc == null) {
            val why = lastError ?: "UserService 未连接"
            lastExecError = why
            return -1 to why
        }
        return try {
            val raw = svc.exec(command)
            val idx = raw.indexOf('\n')
            if (idx < 0) {
                // 服务端异常分支返回的是没有换行的 "-1 换行 异常原文"，原文即原因。
                if (raw.startsWith("java.") || raw.startsWith("android.")) lastExecError = raw
                -1 to raw
            } else {
                lastExecError = null
                (raw.substring(0, idx).toIntOrNull() ?: -1) to raw.substring(idx + 1)
            }
        } catch (t: Throwable) {
            lastExecError = t.toString()
            -1 to t.toString()
        }
    }

    // ---------------------------------------------------------------- root 通道（9.289）

    /**
     * payload 成功后留下的 su 通道。
     *
     * 9.288 的教训：我们的 ksu_stage.sh 一直在 uid=2000 下跑，连管理器包里的 ksud 都读不到
     * （/data/app 不可读），最后那句 "late-load skipped: kernelsu already loaded" 是假成功 ——
     * 模块是 payload 装的，管理器 appid 却是 payload 自己认的包名，所以 MapleSu/XEC 都显示未安装。
     * 候选按参考实现可能落地的位置排序，命中一个就缓存；命中判据只有 `id -u` == 0。
     */
    private val ROOT_CANDIDATES = listOf(
        "/data/local/tmp/su -c",
        "su -c",
        "/system/bin/su -c",
        "/data/local/tmp/ksud su -c",
    )

    @Volatile private var rootPrefix: String? = null
    @Volatile private var rootProbed = false

    /** 用 root 通道执行一条 shell 命令；没有通道返回 (255, "no root channel")。 */
    /**
     * 9.289: probe the su channel once and cache it. force=true re-probes (the payload may
     * have just installed one). The only accepted proof is `id -u` == 0.
     */
    fun probeRoot(force: Boolean = false): String? {
        if (!force) {
            val cached = rootPrefix
            if (cached != null) return cached
            if (rootProbed) return null
        }
        rootProbed = true
        rootPrefix = null
        for (cand in ROOT_CANDIDATES) {
            val r = exec(cand + " " + shQuote("id -u 2>&1"))
            if (r.first != 0) continue
            val v = r.second.lineSequence().map { it.trim() }.lastOrNull { it.isNotEmpty() } ?: continue
            if (v == "0") {
                rootPrefix = cand
                return cand
            }
        }
        return null
    }

    fun execRoot(command: String): Pair<Int, String> {
        val prefix = probeRoot() ?: return 255 to "no root channel"
        return exec(prefix + " " + shQuote(command))
    }

    private fun shQuote(s: String): String = "'" + s.replace("'", "'\\''") + "'"

    // ---------------------------------------------------------------- 推文件

    /**
     * 9.294：无状态分块推文件。
     *
     * 每块都是独立的一次 binder 事务（自带 truncate 标记），所以 UserService 进程
     * 在两块之间换代 —— Shizuku 的 wrapper 会透明重连到新进程 —— 也不会丢状态：
     * 新进程照样按「首块截断、其余追加」把剩下的块写进去。旧的 fileOpen/fileWrite/
     * fileClose 三步协议在这种情况下只能抛 "fileOpen() 还没调用"（9.293 真机日志）。
     */
    fun pushFile(path: String, bytes: ByteArray, executable: Boolean = true): Pair<Int, String> {
        val mode = if (executable) 493 else 420
        var attempt = 0
        while (true) {
            val svc = service ?: return -1 to (lastError ?: "UserService 未连接")
            var onDevice = -1L
            val err = try {
                var parts = FilePush.plan(bytes.size)
                // 空文件也要落盘并按 mode chmod：plan() 会给一个 len=0 的首末块。
                if (parts.isEmpty()) parts = listOf(FilePush.Part(0, 0, true, true))
                for (p in parts) {
                    val chunk = if (p.len == bytes.size) bytes else bytes.copyOfRange(p.offset, p.offset + p.len)
                    onDevice = svc.filePut(path, chunk, p.truncate, if (p.last) mode else -1)
                }
                // 9.295：不信 binder 的「没抛异常」，以服务端 stat 出来的长度为准。
                // 9.294 真机就是「返回 0 但文件不存在」，deploy 的 mv 才报 ENOENT。
                lastPushInfo = "parts=" + parts.size + " ondev=" + onDevice + " want=" + bytes.size
                if (onDevice != bytes.size.toLong()) {
                    "short write: device has " + onDevice + " B, want " + bytes.size + " B"
                } else null
            } catch (t: Throwable) {
                lastPushInfo = "parts=? ondev=" + onDevice + " want=" + bytes.size + " exc=" + t
                t.toString()
            }
            if (err == null) {
                lastExecError = null
                return 0 to ""
            }
            lastExecError = err
            if (attempt >= 2) return -1 to err
            // 换代后再推一遍：整份重写（首块 truncate=true），不会留下半截文件。
            // 9.295：给两次重试 —— 9.294 只重试一次，遇到「刚换代 + 首块丢失」就整条链挂掉。
            attempt++
            disconnect()
            val ctx = appContext ?: return -1 to err
            runCatching { connect(ctx) }
        }
    }

    // ---------------------------------------------------------------- 读文件

    // ---------------------------------------------------------------- 流式执行

    class StreamSession internal constructor(
        val input: InputStream,
        private val exit: AtomicInteger,
        private val done: CountDownLatch,
        private val readEnd: ParcelFileDescriptor,
    ) {
        fun exitCodeOrNull(): Int? = if (done.count == 0L) exit.get() else null

        fun close() {
            runCatching { input.close() }
            runCatching { readEnd.close() }
        }
    }

    fun stream(command: String): StreamSession? {
        val svc = service ?: return null
        val pipe = ParcelFileDescriptor.createPipe()
        val readEnd = pipe[0]
        val writeEnd = pipe[1]
        val input = ParcelFileDescriptor.AutoCloseInputStream(readEnd)
        val code = AtomicInteger(Int.MIN_VALUE)
        val done = CountDownLatch(1)

        Thread {
            try {
                code.set(svc.execStream(command, writeEnd))
            } catch (t: Throwable) {
                code.set(-1)
            } finally {
                runCatching { writeEnd.close() }
                done.countDown()
            }
        }.apply {
            isDaemon = true
            name = "extract-stream"
        }.start()

        return StreamSession(input, code, done, readEnd)
    }
}
