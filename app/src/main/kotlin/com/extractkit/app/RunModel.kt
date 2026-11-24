package com.extractkit.app

import android.app.Application
import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

internal const val SHIZUKU_PKG = "moe.shizuku.privileged.api"

/**
 * 9.338: 授权类失败一旦授权成功就该消失，否则横幅永远停在「需要授权」，
 * 看起来像「从 Shizuku 回来不会自动更新」。链路失败（self cell / CHAIN_STOP）不算。
 */
internal fun isAuthFail(reason: String): Boolean {
    val s = reason.lowercase()
    return s.contains("unauthorized") || s.contains("permission") || s.contains("auth") ||
        s.contains("shizuku") || reason.contains("授权")
}

/** Shizuku 的四种可用状态，决定了横幅文案与点击行为。 */
internal enum class ShellState { ABSENT, NO_PERM, GRANTED, CONNECTED }

internal enum class BannerAction { NONE, INSTALL_SHIZUKU, REQUEST_PERM, OPEN_MANAGER, SHOW_LOG }

internal data class Banner(
    val title: String,
    val sub: String,
    val accent: Long,
    val action: BannerAction,
)

/** 纯函数，便于单测：把内部状态翻译成横幅。 */
internal fun bannerFor(
    shell: ShellState,
    rooted: Boolean,
    busy: Boolean,
    stage: String,
    lastFail: String?,
    /**
     * 9.384：本次开机已经成功过一次（prefs 里 last_ok_boot == 当前 boot_id）。
     * 成功一次后 UAF 资源就用掉了，同一次开机重跑没有意义，而且 Shizuku 掉线
     * 也改变不了「已经 root」这个事实 —— 所以它要压过「未检测到 Shizuku」。
     */
    succeededThisBoot: Boolean = false,
    okManagerPkg: String? = null,
): Banner = when {
    busy -> Banner("执行中", stage.ifBlank { "正在准备…" }, 0xFF9A6A00, BannerAction.SHOW_LOG)
    // 失败但还没拿到 shell 上下文：点状态栏先申请授权，别直接甩一屏日志
    // 失败优先：本次跑失败了就报失败，不能因为「设备本来就有 root」显示成
    // 已提权（那是上一次或别的来源的 root）。
    lastFail != null && shell != ShellState.CONNECTED ->
        Banner("需要授权", "点这里打开 Shizuku 授权，回来自动刷新", 0xFF9A6A00, BannerAction.REQUEST_PERM)
    lastFail != null -> Banner("未成功", lastFail, 0xFFC2410C, BannerAction.SHOW_LOG)
    rooted -> Banner("已提权", "su 可用，点这里打开管理器", 0xFF12A150, BannerAction.OPEN_MANAGER)
    succeededThisBoot -> Banner(
        "已提权",
        if (okManagerPkg.isNullOrBlank()) "本次开机已成功，重启前不用再跑"
        else "本次开机已成功，点这里打开管理器",
        0xFF12A150,
        if (okManagerPkg.isNullOrBlank()) BannerAction.NONE else BannerAction.OPEN_MANAGER,
    )
    shell == ShellState.ABSENT ->
        Banner("环境受限", "未检测到 Shizuku，点这里安装", 0xFF9A6A00, BannerAction.INSTALL_SHIZUKU)
    shell == ShellState.NO_PERM ->
        Banner("需要授权", "点这里打开 Shizuku 授权，回来自动刷新", 0xFF9A6A00, BannerAction.REQUEST_PERM)
    else -> Banner("就绪", "点下方按钮开始", 0xFF12A150, BannerAction.NONE)
}

internal fun shouldAutoOpenManager(ok: Boolean, rooted: Boolean, pkg: String?): Boolean =
    ok && rooted && !pkg.isNullOrBlank()

internal fun backendOf(
    prefCalib: Boolean,
    ghost: Boolean = false,
    wacom: Boolean = false,
    wacomMode: String = "no-tracefs",
): String =
    when {
        // 9.328: three branches of the same reference chain, all CVE-2026-99491.
        wacom -> "CVE-2026-99491 · " + when (wacomMode) {
            "tracefs" -> "tracefs 分支"
            "no-tracefs" -> "no-tracefs 分支"
            else -> "real_cred 分支"
        }
        ghost -> "CVE-2026-98260 · ghost 链"
        prefCalib -> "CVE-2026-98937 · perf 标定"
        else -> "CVE-2026-98260 · posix timer UAF"
    }

/**
 * 首页的执行宿主：环境探测、Shizuku 授权、跑链、失败原因、成功后跳管理器。
 * 逻辑放 ViewModel 里，旋转屏幕/切后台都不会把正在跑的链丢掉。
 */
internal class RunModel(app: Application) : AndroidViewModel(app) {

    private val store = LogStore(app)

    private val engine = ExtractEngine(app, ::log, ::stage)

    var shellState by mutableStateOf(ShellState.ABSENT)
        private set
    var rooted by mutableStateOf(false)
        private set
    var busy by mutableStateOf(false)
        private set
    var stage by mutableStateOf("")
        private set
    var lastFail by mutableStateOf<String?>(null)
        private set

    /** 9.384：本次开机已经成功过一次 —— 由 prefs 的 boot_id 决定，不看 Shizuku。 */
    var succeededThisBoot by mutableStateOf(false)
        private set

    /** 9.384：上次成功时用的管理器包名，Shizuku 不在时也能直接把它拉起来。 */
    var okManagerPkg by mutableStateOf<String?>(null)
        private set

    val logs = mutableStateListOf<String>()

    /** 成功后要打开的包名；Activity 消费后置空。 */
    var openManager by mutableStateOf<String?>(null)
        private set

    val banner: Banner
        get() = bannerFor(shellState, rooted, busy, stage, lastFail, succeededThisBoot, okManagerPkg)

    /** 9.384：这次开机「已提权」只往日志里写一次。 */
    private var bootSuccessLogged = false

    /** 只有点过「开始提权」才落盘；平时打开软件不生成日志文件。 */
    private var persistLogs = false

    fun log(line: String) {
        ringAppend(logs, line, 600)
        if (persistLogs) store.append(line)
    }

    private fun stage(text: String) {
        stage = text
    }

    /** 探测一次环境；从管理器/标定页回来、授权回调后都要调。 */
    fun refresh() {
        viewModelScope.launch {
            val state = withContext(Dispatchers.IO) {
                when {
                    !Shell.alive() -> ShellState.ABSENT
                    !Shell.granted() -> ShellState.NO_PERM
                    Shell.connected() -> ShellState.CONNECTED
                    else -> ShellState.GRANTED
                }
            }
            shellState = state
            // 9.338: 授权成功后清掉授权类失败，横幅才会自己转绿；链路失败保留当证据
            if (state == ShellState.CONNECTED) {
                val stale = lastFail
                if (stale != null && isAuthFail(stale)) lastFail = null
            }
            if (state == ShellState.GRANTED) {
                // 授权了但还没连上，顺手连一次，省得用户点按钮才等
                withContext(Dispatchers.IO) { runCatching { Shell.connect(getApplication()) } }
                if (Shell.connected()) shellState = ShellState.CONNECTED
            }
            rooted = if (shellState == ShellState.CONNECTED) {
                withContext(Dispatchers.IO) { runCatching { engine.hasRootNow() }.getOrDefault(false) }
            } else {
                // Shizuku 不可用时退回直接问 su（KSU 已接管的情况）
                withContext(Dispatchers.IO) { runCatching { probeSuDirectly() }.getOrDefault(false) }
            }
            // 9.384：boot 级成功记录。直接读 /proc（不经 Shizuku），这样 Shizuku
            // 没启动/没授权时首页也不再喊「环境受限」，而是显示这次开机已经提权。
            val prefs = getApplication<Application>()
                .getSharedPreferences("run", android.content.Context.MODE_PRIVATE)
            val okBoot = prefs.getString("last_ok_boot", null)
            okManagerPkg = prefs.getString("last_ok_manager", null)?.takeIf { it.isNotBlank() }
            val nowBoot = withContext(Dispatchers.IO) { ExtractEngine.localBootId() }
            succeededThisBoot = !okBoot.isNullOrBlank() && okBoot == nowBoot
            if (succeededThisBoot && !bootSuccessLogged) {
                bootSuccessLogged = true
                log("\u00b7 this boot is already rooted (boot_id=" + nowBoot.take(8) + "); no Shizuku needed")
            }
            // 注意：不要因为「su 现在能用」就把刚才的失败擦掉（那是上一次诊断的证据）
            if (AppState.needsReprobe) {
                AppState.needsReprobe = false
                log("· env changed, re-probing")
            }
        }
    }

    /**
     * 点横幅的那一刻必须「有反应」：
     *  - binder 没起来（Shizuku 没点启动）→ 直接打开 Shizuku，让用户点 Start；
     *  - binder 正常 → 拉系统授权弹窗，2.5 s 没弹出来（部分 ROM）就打开 Shizuku 手动授权。
     * 返回时 Activity 的 ON_RESUME 会再 refresh 一次，授权状态自动更新。
     */
    fun requestPermission() {
        val alive = runCatching { Shell.alive() }.getOrDefault(false)
        if (!alive) {
            log("! shizuku service is not running; opening Shizuku so you can start it")
            stage = "Shizuku 未运行"
            openApp = SHIZUKU_PKG
            return
        }
        Shell.requestPermission()
        log("· shizuku auth requested; allow the prompt (or grant it inside Shizuku)")
        stage = "等待 Shizuku 授权"
        viewModelScope.launch {
            kotlinx.coroutines.delay(2500)
            val ok = runCatching { Shell.granted() }.getOrDefault(false)
            if (!ok) {
                log("· no grant yet; opening Shizuku for a manual allow")
                openApp = SHIZUKU_PKG
            }
            refresh()
        }
    }

    fun consumeOpenManager(): String? {
        val pkg = openManager
        openManager = null
        return pkg
    }


    /** 当前进程装不下 Shizuku 的授权弹窗时，由 Activity 负责把它拉到前台。 */
    var openApp by mutableStateOf<String?>(null)
        private set

    fun consumeOpenApp(): String? {
        val pkg = openApp
        openApp = null
        return pkg
    }

    /**
     * 跑一次链。EK-CORE 走自带 payload；EK-CALIB 目前仍由旧入口承担（下一步迁），
     * 这里先给出明确提示，避免静默什么都不做。
     */
    private var runSeq = 0

    fun start(managerPkg: String?) {
        if (busy) {
            log("· previous run still busy; trigger ignored")
            return
        }
        // 点「开始提权」才开始记日志（含新建文件），打开软件时不生成
        persistLogs = true
        lastFail = null
        busy = true
        stage = "准备"
        val rid = ++runSeq
        log("· run#$rid start (busy=false)")
        viewModelScope.launch {
            try {
                if (managerPkg.isNullOrBlank()) {
                    lastFail = "no root manager detected; long-press the manager row to pick one"
                    return@launch
                }
                if (!engine.ensureShell()) {
                    val why = Shell.error() ?: "start Shizuku and grant access first"
                    log("! shell unavailable: $why")
                    // 能 ping 到 Shizuku 但没授权时，直接把系统授权弹窗拉起来
                    if (why.contains("unauthorized")) {
                        runCatching { Shell.requestPermission() }
                        lastFail = "$why. auth prompt shown; allow it then tap Start again"
                    } else {
                        lastFail = why
                    }
                    return@launch
                }
                val useCALIB = getApplication<Application>()
                    .getSharedPreferences("backend", Context.MODE_PRIVATE)
                    .getBoolean("useCALIB", false)
                if (useCALIB) {
                    runCalib(managerPkg)
                    return@launch
                }
                val safeMode = getApplication<Application>()
                    .getSharedPreferences("run", Context.MODE_PRIVATE)
                    .getBoolean("safe_mode", false)
                if (safeMode) log("· safe mode: on")
                log("==== start: one-tap extract (uid0) ====")
                log("· manager: $managerPkg")
                val mode = Modes.byId("chain_uid0")
                // 9.217: remember boot_id + uptime of this attempt. A run that ends with the
                // kernel crashing reboots the device; retrying then is not free, it just rolls
                // the same dice once more (and burns another reboot).
                // 9.359：只有真 uuid 才算 boot_id，Shizuku 掉线时这条命令会回异常文本。
                val bootBefore = ExtractEngine.bootIdOf(
                    Shell.exec("cat /proc/sys/kernel/random/boot_id 2>/dev/null").second
                )
                val upBefore = android.os.SystemClock.elapsedRealtime()
                var outcome = engine.run(mode, false, ::stage, managerPkg, safeMode)
                log("---- result: ${outcome.stage} ok=${outcome.ok} ----")
                // 6.6 的假 cred 页有概率被内核回收后装满别的对象，uid 读到脏值，
                // 这一趟必然失败；重跑一次就是全新子进程 + 全新假 cred 页，
                // 实测能把这一类的失效率从 ~6% 压到 ~0.4%。
                // 不允许重跑的只有「已放弃写入/驻留等重启」这类现场（重跑会踩同一页）。
                var attempt = 1
                // 9.347：失败就是可以再跑——不再限制「每次只能跑一趟」，也不再默认关掉
                // 自动重跑。只有四种现场会停：需要重启的 stage（重跑会踩同一页）、
                // 跑到一半已经重启（内核崩了）、本机已经成功过（SAME_BOOT，写已释放对象）、
                // 以及用户自己把 allow_retry 关掉。
                val allowRetry = getApplication<Application>()
                    .getSharedPreferences("run", Context.MODE_PRIVATE)
                    .getBoolean("allow_retry", true)
                while (!outcome.ok && allowRetry) {
                    val bad = outcome.stage
                    // 9.218：payload 现在「没有页级证据就不写」，这一刻它会把上一趟的
                    // 牺牲线程留在驻留状态（zombie held），同一开机内再来一次只会再攒一个。
                    // 9.425：回到上游 —— armed 之后 payload 永不退出（park_holder 常驻），
                    // 同一开机的第二次 fire 会被它自己的 PARKED 挡住。这几种现场重跑只会再攒
                    // 一个驻留对象，直接停，提示重启。
                    if (bad.contains("PARKED") || bad.contains("held") || bad.contains("zombie") ||
                        bad.contains("no page window") || bad.contains("fake cred write failed")
                    ) {
                        log("[retry] stop: $bad - payload is parked (upstream behaviour); reboot before another run")
                        break
                    }
                    // 9.359：同一套判据，但读到的文本必须先过 uuid 校验。之前直接拿 trim()
                    // 的文本比，Shizuku 一断线就得到 "Shizuku not running ..."，跟旧值永远
                    // 不等 → 误判「内核崩了重启」并跳过重跑（日志里那句
                    // "boot caf9930c -> Shizuku , "）。
                    val bootNow = ExtractEngine.bootIdOf(
                        Shell.exec("cat /proc/sys/kernel/random/boot_id 2>/dev/null").second
                    )
                    val upNow = android.os.SystemClock.elapsedRealtime()
                    val rebooted = (bootBefore.isNotEmpty() && bootNow.isNotEmpty() && bootNow != bootBefore) ||
                        upNow < upBefore
                    if (bootNow.isEmpty() && !(upNow < upBefore))
                        log("[retry] boot_id unreadable; assuming the same boot and retrying")
                    if (rebooted) {
                        log(
                            "[retry] skip: device rebooted during the run (boot " + bootBefore.take(8) +
                                " -> " + bootNow.take(8).ifEmpty { "?" } + ", uptime " + (upNow / 1000) +
                                "s) - the kernel crashed"
                        )
                        break
                    }
                    // 9.371: the retry path calls engine.run() directly, so when Shizuku died mid-chain
                    // every round burned three bind attempts and still got nowhere. Two stops:
                    // no shell at all, and a hard cap on rounds.
                    if (!Shell.connected()) {
                        log("[retry] stop: shell is gone (" + (Shell.error() ?: "Shizuku down") + "); start it again then retry")
                        break
                    }
                    attempt++
                    log("[retry] attempt $attempt (previous: $bad)")
                    Thread.sleep(600)
                    stage = "retry $attempt"
                    outcome = engine.run(mode, false, ::stage, managerPkg, safeMode)
                    log("---- result(try $attempt): ${outcome.stage} ok=${outcome.ok} ----")
                }
                if (!outcome.detail.isBlank()) log(outcome.detail)
                // hasRootNow() 依赖 Shizuku shell 还活着；链路自己已经读到
                // 「su → uid=0(root)」时，不能因为 shell 断开就把成功判成失败。
                // 只用本轮结果：hasRootNow() 分不清「本来就有 root」和
                // 「这次刚拿到 root」，把既有 root 当成功会误报。
                val okRoot = outcome.ok
                rooted = okRoot
                if (shouldAutoOpenManager(outcome.ok, okRoot, managerPkg)) {
                    lastFail = null          // 成功必须清掉上一轮的失败原因
                    log("✓ rooted; open manager")
                    // 9.395: no hand-off watch. late-load is done by the time the chain reports
                    // success, so the manager is opened once, right here.
                    openManager = managerPkg
                } else {
                    lastFail = outcome.stage.ifBlank { "uid=0 not confirmed" }
                    log("! failed: $lastFail")
                }
            } catch (t: Throwable) {
                lastFail = t.message ?: t.javaClass.simpleName
                log("! exception: ${t.message ?: t.javaClass.simpleName}")
            } finally {
                busy = false
                stage = ""
                persistLogs = false          // 下一轮 start() 再打开，避免常驻写盘
                // 不要无条件 refresh：它会用 hasRootNow() 覆盖本轮判定
                // （成功后 Shell 断开时会把「已提权」翻回「未就绪」）。
                if (!rooted) refresh()
            }
        }
    }

    /**
     * EK-CALIB：只用我们自己的标定器拿 slide，注入仍走 EK-CORE 的窗口判据。
     *
     * EK-CALIB 的注入路径依赖 `mm_page_*` / `kmem_cache_free` 的 enable，那种权限
     * 在多数机器上拿不到；而它的 perf callchain 通道不需要任何 tracefs 权限，
     * 所以这里把它降级成「标定器」：slide → EXTRACTKIT_SLIDE → EK-CORE 引擎。
     */
    private suspend fun runCalib(managerPkg: String) {
        val app = getApplication<Application>()
        log("==== start: CVE-2026-98937 calibrate -> CVE-2026-98260 inject ====")
        log("· manager: $managerPkg")

        // 同一次开机只能安全跑一次（UAF 是一次性资源；注入成功后还会留下驻留进程 + 僵尸）。
        // EK-CORE 分支由 ExtractEngine 判；EK-CALIB 走自己的前置流程，必须自己判一次。
        val bootId = runCatching {
            Shell.exec("cat /proc/sys/kernel/random/boot_id 2>/dev/null").second.trim()
        }.getOrDefault("")
        val prefs = app.getSharedPreferences("run", android.content.Context.MODE_PRIVATE)
        val lastOk = prefs.getString("last_ok_boot", null)
        if (bootId.isNotEmpty() && bootId == lastOk) {
            log("[guard] already succeeded this boot (boot_id=${bootId.take(8)}); refuse repeat run")
            busy = false
            lastFail = "already rooted once this boot; one run per kernel, reboot to retry"
            return
        }
        log("[guard] boot_id=${bootId.take(8).ifEmpty { "?" }} lastOk=${lastOk?.take(8) ?: "none"}")

        val allowed = EkCalib.tracefsAllowed(app)
        log("· tracefs check: ${if (allowed) "ok" else "restricted (calibration uses perf)"}")

        stage = "CVE-2026-98937 · 事件自检"
        EkCalib.preflight(app, ::log)

        stage = "CVE-2026-98937 · 标定（自有）"
        val own = EkCalib.calibrateOwn(app, ::log)
        val slideHex: String?
        if (own == null) {
            slideHex = null
            log("! calibration gave no slide: fall back to CVE-2026-98260 base (call_site); inject anyway")
        } else {
            slideHex = own.first
            val pageHex = own.second.ifBlank { "0xffffff7f80000000" }
            log("✓ calibrate: slide=$slideHex page_offset=$pageHex")
        }

        stage = "CVE-2026-98937 · 注入（CVE-2026-98260 判据）"
        val out = withContext(Dispatchers.IO) {
            engine.run(
                Modes.byId("chain_uid0"),
                allowUnmatched = true,
                onStageUpdate = ::log,
                managerPkg = managerPkg,
                safeMode = false,
                slideHex = slideHex,
                pfnBaseHex = own?.second?.ifBlank { null },
            )
        }
        // 先认链路自报的成功，再用 su 复核；不能只看 hasRootNow()。
        val rootedNow = out.ok ||
            withContext(Dispatchers.IO) { runCatching { engine.hasRootNow() }.getOrDefault(false) }
        rooted = rootedNow
        if (rootedNow) {
            log("✓ rooted (CVE-2026-98937 calibrate + CVE-2026-98260 inject); open manager")
            if (bootId.isNotEmpty()) {
                prefs.edit().putString("last_ok_boot", bootId).apply()
                log("[guard] recorded success for this boot (boot_id=${bootId.take(8)})")
            }
            openManager = managerPkg
        } else {
            lastFail = if (out.ok) "flow finished without root" else "CVE-2026-98260 criteria did not reach uid=0 (see log)"
            log("! $lastFail")
        }
    }

    private fun probeSuDirectly(): Boolean = parseSuUid(
        runCatching {
            val p = ProcessBuilder("/system/bin/sh", "-c", "su -c id 2>/dev/null || /system/bin/su -c id 2>/dev/null")
                .redirectErrorStream(true)
                .start()
            // 没有 su 时 `su -c id` 会一直等授权，必须有上限。
            if (!p.waitFor(3, java.util.concurrent.TimeUnit.SECONDS)) {
                p.destroyForcibly()
                return@runCatching ""
            }
            p.inputStream.bufferedReader().readText()
        }.getOrDefault("")
    )
}
