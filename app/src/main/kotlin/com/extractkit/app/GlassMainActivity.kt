package com.extractkit.app

import androidx.compose.animation.core.animateFloat
import androidx.compose.ui.graphics.nativeCanvas

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import rikka.shizuku.Shizuku
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.foundation.clickable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.clipPath
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asComposeRenderEffect
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.material3.Text
import com.kyant.backdrop.backdrops.rememberLayerBackdrop
import com.kyant.backdrop.drawBackdrop
import com.kyant.backdrop.effects.blur
import com.kyant.backdrop.effects.lens
import com.kyant.backdrop.effects.vibrancy
import com.kyant.backdrop.highlight.Highlight
import com.kyant.backdrop.backdrops.layerBackdrop
import com.kyant.backdrop.shadow.InnerShadow
import com.kyant.backdrop.shadow.Shadow
import com.kyant.shapes.RoundedRectShape

/** su -c id 的输出里是否真的拿到了 uid=0（"uid=2000" 不算）。 */
internal fun parseSuUid(output: String): Boolean =
    output.lineSequence().any { line ->
        line.contains("uid=0(") || line.trim().startsWith("uid=0 ")
    }

private val MANAGERS = linkedMapOf(
    "com.sukisu.ultra" to "SukiSU",
    "io.milksu.manager" to "MilkSU",
    "com.milkcode" to "MilkSU（旧包名）",
    "me.weishu.kernelsu" to "KernelSU",
    "com.resukisu.resukisu" to "SukiSU（旧包名）",
    "com.ghostlock.ksu" to "GhostLock KSU",
    "org.bakasu.bakasu" to "KernelSU Next",
    "com.kowx712.supermanager" to "SuperManager",
    "dev.maplesu.manager" to "MapleSU",
    "com.rifsxd.ksunext" to "KernelSU Next (ksunext)",
    "com.xecpro.kernel" to "XecPro",
    "com.sukisu.nova" to "SukiSU Nova",
    "com.kaixin.ksu" to "KaixinKSU",
)

internal enum class SheetKind { BACKEND, MANAGER, LOG, SUPPORT, KERNEL }

class GlassMainActivity : ComponentActivity() {

    private val model: RunModel by viewModels()

    private val permListener = Shizuku.OnRequestPermissionResultListener { _, grantResult ->
        model.log("· Shizuku grant result: ${if (grantResult == 0) "allowed" else "denied"}($grantResult)")
        model.refresh()
    }

    // 9.338: Shizuku 启停（binder 上线/掉线）时自己刷新，不必等用户切回来
    private val binderUp = Shizuku.OnBinderReceivedListener {
        model.log("· Shizuku binder is up")
        model.refresh()
    }

    private val binderDown = Shizuku.OnBinderDeadListener {
        model.log("· Shizuku binder went down")
        model.refresh()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        EkTheme.load(this)
        val device = "${Build.MANUFACTURER} ${Build.MODEL}".replaceFirstChar { it.uppercase() }
        val kernel = System.getProperty("os.version") ?: "?"
        val backendPrefs = getSharedPreferences("backend", Context.MODE_PRIVATE)
        runCatching { Shizuku.addRequestPermissionResultListener(permListener) }
        runCatching { Shizuku.addBinderReceivedListener(binderUp) }
        runCatching { Shizuku.addBinderDeadListener(binderDown) }

        setContent {
            // 主题动画与状态栏反色都搬进 ThemeRuntime：根作用域不再读 EkTheme.dark，
            // 按下开关时就不用整屏重组一次（那一下正是"刚切换时卡一下"）。
            val barTint = androidx.compose.runtime.remember {
                { dark: Boolean ->
                    if (Build.VERSION.SDK_INT >= 30) {
                        val bars = android.view.WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or
                            android.view.WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS
                        window.insetsController?.setSystemBarsAppearance(if (dark) 0 else bars, bars)
                    }
                }
            }
            ThemeRuntime(barTint)
            var sheet by remember { mutableStateOf<SheetKind?>(null) }
            var backendCALIB by remember { mutableStateOf(backendPrefs.getBoolean("useCALIB", false)) }
            var backendGhost by remember { mutableStateOf(backendPrefs.getBoolean("useGhost", false)) }
            var backendWacom by remember { mutableStateOf(backendPrefs.getBoolean("useWacom", false)) }
            var backendWacomMode by remember {
                mutableStateOf(backendPrefs.getString("wacomMode", "no-tracefs") ?: "no-tracefs")
            }
            val adapt = remember(backendGhost, backendCALIB, backendWacom, kernel) {
                adaptLabel(kernel, backendGhost, backendCALIB, backendWacom)
            }
            val choice = remember(backendCALIB, model.rooted, sheet) {
                val ov = managerOverride()
                // 手动选的应用可能不在已知 8 家里，名字从 PackageManager 取，别直接显示包名
                val labels = if (ov != null && ov !in MANAGERS) {
                    MANAGERS + mapOf(ov to appLabel(ov))
                } else MANAGERS
                ManagerChooser.choose(ov, installedPkgs(), MANAGERS.keys.toList(), labels)
            }
            val lifecycleOwner = LocalLifecycleOwner.current

            LaunchedEffect(Unit) { model.refresh() }

            DisposableEffect(lifecycleOwner) {
                val obs = LifecycleEventObserver { _, event ->
                    if (event == Lifecycle.Event.ON_RESUME) model.refresh()
                }
                lifecycleOwner.lifecycle.addObserver(obs)
                onDispose { lifecycleOwner.lifecycle.removeObserver(obs) }
            }

            // 成功后自动打开管理器
            // 一点「开始提权」就把运行日志推上来，进度直接可见
            LaunchedEffect(model.busy) {
                if (model.busy) sheet = SheetKind.LOG
            }

            LaunchedEffect(model.openManager) {
                val pkg = model.consumeOpenManager() ?: return@LaunchedEffect
                val intent = packageManager.getLaunchIntentForPackage(pkg)
                if (intent == null) {
                    model.log("! cannot open $pkg (no launcher activity)")
                    return@LaunchedEffect
                }
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED)
                // 9.395: open it once, right away - no 900 ms step-back and no five restarts.
                val okOpen = runCatching { startActivity(intent) }.isSuccess
                model.log("· manager open " + (if (okOpen) "ok" else "failed") + " ($pkg)")
                if (!okOpen) model.log("! open the manager by hand")
            }

            // 9.338: 点「需要授权」时真的把 Shizuku 拉到前台（binder 没起来 / 弹窗没出来）
            LaunchedEffect(model.openApp) {
                val pkg = model.consumeOpenApp() ?: return@LaunchedEffect
                val intent = packageManager.getLaunchIntentForPackage(pkg)
                if (intent != null) {
                    startActivity(intent)
                    // 从 Shizuku 回来时 ON_RESUME 会再刷一次；这里多兜一层，防止某些 ROM 不回调
                    model.refresh()
                } else {
                    model.log("! Shizuku ($pkg) is not installed")
                }
            }

            // 日志随时可开：面板自己会去读落盘历史（默认最新一份 = 上次提权），
            // 没提权过也能开，里面提示"还没有日志"。
            val openLog: () -> Unit = { sheet = SheetKind.LOG }

            val runPrefs = remember { getSharedPreferences("run", MODE_PRIVATE) }
            var safeMode by remember {
                mutableStateOf(runPrefs.getBoolean("safe_mode", false))
            }
            val pageBackdrop = com.kyant.backdrop.backdrops.rememberLayerBackdrop()
            androidx.compose.runtime.CompositionLocalProvider(
                LocalBackdrop provides pageBackdrop,
            ) {
            GlassHome(
                pageBackdrop = pageBackdrop,
                onTheme = { EkTheme.toggle(this) },
                device = device,
                kernel = kernel,
                manager = choice.summary,
                backendLabel = backendOf(backendCALIB, backendGhost, backendWacom, backendWacomMode),
                adaptLabel = adapt,
                banner = model.banner,
                busy = model.busy,
                safeMode = safeMode,
                onSafeMode = { on ->
                    safeMode = on
                    runPrefs.edit().putBoolean("safe_mode", on).apply()
                },
                onLog = openLog,
                onBanner = {
                    when (model.banner.action) {
                        BannerAction.INSTALL_SHIZUKU -> {
                            val i = packageManager.getLaunchIntentForPackage(SHIZUKU_PKG)
                            if (i != null) startActivity(i)
                            else model.log("! Shizuku ($SHIZUKU_PKG) not installed")
                        }
                        BannerAction.REQUEST_PERM -> model.requestPermission()
                        BannerAction.OPEN_MANAGER -> {
                            // 9.384: after a successful boot with Shizuku gone, the selected
                            // manager is unknown; fall back to the one the run recorded.
                            val pkg = choice.pkg ?: model.okManagerPkg
                            val i = pkg?.let { packageManager.getLaunchIntentForPackage(it) }
                            if (i != null) startActivity(i) else sheet = SheetKind.MANAGER
                        }
                        BannerAction.SHOW_LOG -> openLog()
                        BannerAction.NONE -> Unit
                    }
                },
                onRun = { model.start(choice.pkg) },
                onCalib = { open(GlassCalibrationActivity::class.java) },
                onBackend = { sheet = SheetKind.BACKEND },
                onManager = { sheet = SheetKind.MANAGER },
                onSupport = { sheet = SheetKind.SUPPORT },
                onKernel = { sheet = SheetKind.KERNEL },
            )

            // 关闭时保留最后一帧内容做「收下去」动画：sheet 变 null 但 held 还记着是谁
            var held by remember { mutableStateOf<SheetKind?>(null) }
            if (sheet != null) held = sheet
            BackHandler(enabled = sheet != null) { sheet = null }

            // 遮罩单独一层：面板收下去的过程中保持变暗，等面板完全退出后才淡出。
            val scrimAlpha = androidx.compose.runtime.remember { androidx.compose.animation.core.Animatable(0f) }
            androidx.compose.runtime.LaunchedEffect(sheet) {
                if (sheet != null) {
                    scrimAlpha.animateTo(
                        1f,
                        androidx.compose.animation.core.tween(
                            durationMillis = 170,
                            easing = androidx.compose.animation.core.FastOutSlowInEasing,
                        ),
                    )
                } else {
                    // 面板 210ms 退出，遮罩同步 200ms 淡出：底面在面板离场时一起变亮，
                    // 面板完全消失时遮罩正好到头，不留尾巴。
                    scrimAlpha.animateTo(
                        0f,
                        androidx.compose.animation.core.tween(
                            durationMillis = 200,
                            easing = androidx.compose.animation.core.FastOutLinearInEasing,
                        ),
                    )
                }
            }
            if (scrimAlpha.value > 0.001f) {
                val scrimColor = paletteFor(EkTheme.mixCoarse).scrim
                Box(
                    Modifier
                        .fillMaxSize()
                        .background(scrimColor.copy(alpha = scrimColor.alpha * scrimAlpha.value))
                        .clickable(
                            interactionSource = remember { androidx.compose.foundation.interaction.MutableInteractionSource() },
                            indication = null,
                        ) { sheet = null },
                )
            }
            androidx.compose.animation.AnimatedVisibility(
                visible = sheet != null,
                // 面板从屏幕下方顶上来：起点整块在屏幕外，弹簧顶到位时带一点回弹（"弹"出来），
                // 同时淡入；退出就原路往下沉走并淡出。
                enter = androidx.compose.animation.slideInVertically(
                    initialOffsetY = { it },
                    animationSpec = androidx.compose.animation.core.spring<
                        androidx.compose.ui.unit.IntOffset
                        >(dampingRatio = 0.80f, stiffness = 420f),
                ) + androidx.compose.animation.fadeIn(
                    animationSpec = androidx.compose.animation.core.tween(130),
                ),
                exit = androidx.compose.animation.slideOutVertically(
                    targetOffsetY = { it },
                    animationSpec = androidx.compose.animation.core.tween(
                        durationMillis = 210,
                        easing = androidx.compose.animation.core.FastOutLinearInEasing,
                    ),
                ) + androidx.compose.animation.fadeOut(
                    animationSpec = androidx.compose.animation.core.tween(160),
                ),
            ) {
                when (held) {
                    SheetKind.BACKEND -> BackendSheet(onClose = {
                        sheet = null
                        backendCALIB = backendPrefs.getBoolean("useCALIB", false)
                        backendGhost = backendPrefs.getBoolean("useGhost", false)
                        backendWacom = backendPrefs.getBoolean("useWacom", false)
                backendWacomMode = backendPrefs.getString("wacomMode", "no-tracefs") ?: "no-tracefs"
                        AppState.lastBackendCalib = backendCALIB
                    })
                    SheetKind.MANAGER -> ManagerSheet(onClose = { sheet = null; model.refresh() })
                    SheetKind.LOG -> LogSheet(onClose = { sheet = null }, memory = model.logs)
                    SheetKind.SUPPORT -> SupportSheet(onClose = { sheet = null })
                    SheetKind.KERNEL -> KernelSheet(
                        ghost = backendGhost,
                        cCALIB = backendCALIB,
                        wacom = backendWacom,
                        onClose = { sheet = null },
                    )
                    null -> Unit
                }
            }
            }
        }
    }

    override fun onDestroy() {
        runCatching { Shizuku.removeRequestPermissionResultListener(permListener) }
        runCatching { Shizuku.removeBinderReceivedListener(binderUp) }
        runCatching { Shizuku.removeBinderDeadListener(binderDown) }
        super.onDestroy()
    }

    /** 四级文案：本机 cfg > 内置 profile > 已收录（未验证）> 未知 */
    private fun adaptLabel(kernel: String, ghost: Boolean, cCALIB: Boolean, wacom: Boolean = false): String {
        // 执行链路一换，这里跟着换：内核适配只报当前链路真正能跑的内核
        if (wacom) {
            // 9.409：与 ExtractEngine 的放行判据一一对应 —— 内置 profile（7 条，
            // RelMatch 认同一颗内核）、本机标定产物、旧的 WacomCalibrated 前缀名单。
            // 之前这里只看旧前缀名单（只有 6.6 那一条），6.12/6.1 明明内置了也显示
            // 「会拒跑」，是显示层的假警报。
            if (WacomBuiltin.forKernel(kernel) != null) return "已适配（内置 profile）"
            if (runCatching { WacomCalibStore.bytesFor(this, kernel) }.getOrNull() != null) {
                return "已适配（本机标定）"
            }
            if (GhostSupport.profileFor(kernel, WacomCalibrated.RELEASES) != null) {
                return "已适配（CVE-2026-99491 标定）"
            }
            return "未标定 · 导入本机 boot.img 标定后即可跑"
        }
        if (ghost) {
            val prof = GhostSupport.profileFor(kernel)
            return if (prof != null) "已适配（ghost 标定）" else "该链路未适配此内核 · 会拒跑"
        }
        if (cCALIB) {
            val hasCfg = runCatching { ConfigGen.cfgBytesForCurrentKernel(this) != null }.getOrDefault(false)
            if (hasCfg) return "已适配（本机标定）"
            val hit = ConfigGen.PROFILES.firstOrNull { ConfigGen.sameKernel(it.release, kernel) }
            return when {
                hit == null -> "需要本机内核表 · 先标定"
                (hit.symbols["do_timer_create"] ?: 0L) != 0L -> "已适配（内置 profile）"
                else -> "已适配（offsets-only）"
            }
        }
        if (ReleaseMatrix.familyOf(kernel) == null) return "不在六支矩阵内 · 会拒跑"
        if (!ConfigGen.isVulnerable(kernel)) return "该内核不在受影响范围"
        val hasCfg = runCatching { ConfigGen.cfgBytesForCurrentKernel(this) != null }.getOrDefault(false)
        if (hasCfg) return "已适配（本机标定）"
        val hit = ConfigGen.PROFILES.firstOrNull { ConfigGen.sameKernel(it.release, kernel) }
        if (hit != null) {
            // 只带 4 个 cred 锚点的那几条走 offsets-only：没有 do_timer_create，靠尺寸软匹配
            val hasText = (hit.symbols["do_timer_create"] ?: 0L) != 0L
            return if (hasText) "已适配（内置 profile）" else "已适配（offsets-only）"
        }
        val known = runCatching { ConfigGen.knownFor(kernel, android.os.Build.MODEL) }.getOrNull()
        if (known != null) {
            val rate = if (known.success + known.failure > 0) {
                " · 成功率 ${known.success * 100 / (known.success + known.failure)}%"
            } else {
                ""
            }
            return "已收录（未验证，需标定）$rate"
        }
        return "内核未知，点「标定」重试"
    }

    private fun open(cls: Class<*>, autorun: Boolean = false) {
        startActivity(Intent(this, cls).putExtra("autorun", autorun))
    }

    private fun appLabel(pkg: String): String =
        runCatching {
            packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString()
        }.getOrDefault(pkg)

    private fun installedPkgs(): Set<String> =
        packageManager.getInstalledPackages(0).map { it.packageName }.toSet()

    /** 手动指定的管理器：只要还装着就用它（选谁是用户的事，这里只清理「已卸载」的残留）。 */
    private fun managerOverride(): String? {
        val prefs = getSharedPreferences("manager", MODE_PRIVATE)
        val pkg = prefs.getString("pkg", null)?.takeIf { it.isNotBlank() } ?: return null
        val installed = runCatching { packageManager.getApplicationInfo(pkg, 0) }.isSuccess
        if (!installed) {
            prefs.edit().remove("pkg").remove("manual").apply()
            return null
        }
        return pkg
    }
}

/**
 * 主题切换的运行时：动画与状态栏反色只在这里读 EkTheme.dark。
 * 抽成一个独立 composable，是为了让"按下开关"只重组这一小块，
 * 而不是把整个 setContent 连同几十个 Text 一起重组 —— 那一下正是切换瞬间的掉帧来源。
 */
@Composable
private fun ThemeRuntime(barTint: (Boolean) -> Unit) {
    val dark = EkTheme.dark
    // 用 animate 直接写 State，而不是读一个 State 再回写：
    // 后者每帧都会让整个作用域重组、动画 spec 重建 → 动画被反复重启（会卡在半路）。
    LaunchedEffect(dark) {
        androidx.compose.animation.core.animate(
            initialValue = EkTheme.mix,
            targetValue = if (dark) 1f else 0f,
            animationSpec = androidx.compose.animation.core.tween(
                durationMillis = 420,
                easing = androidx.compose.animation.core.FastOutSlowInEasing,
            ),
        ) { v, _ ->
            // 细档位：只被绘制读（揭示圆、星空），每帧都更新
            EkTheme.mix = v
            // 粗档位：16 档，跨档才写，重组最多 16 次而不是每帧一次
            val q = kotlin.math.round(v * 24f) / 24f
            if (q != EkTheme.mixCoarse) EkTheme.mixCoarse = q
        }
        // 收尾对齐到目标值，避免圆停在 0.999 或 0.001
        EkTheme.mix = if (dark) 1f else 0f
        EkTheme.mixCoarse = EkTheme.mix
    }
    LaunchedEffect(dark) { barTint(dark) }
}

@Composable
private fun GlassHome(
    onTheme: () -> Unit,
    device: String,
    kernel: String,
    manager: String,
    backendLabel: String,
    adaptLabel: String,
    banner: Banner,
    busy: Boolean,
    safeMode: Boolean,
    onSafeMode: (Boolean) -> Unit,
    onBanner: () -> Unit,
    onRun: () -> Unit,
    onLog: () -> Unit,
    onCalib: () -> Unit,
    onBackend: () -> Unit,
    onManager: () -> Unit,
    onSupport: () -> Unit,
    onKernel: () -> Unit,
    pageBackdrop: com.kyant.backdrop.backdrops.LayerBackdrop,
) {
    // 真正的 backdrop：先把页面背景录进图层，卡片再从里面“取景”做折射
    val pal = paletteFor(EkTheme.mixCoarse)
    val backdrop = pageBackdrop
    val density = LocalDensity.current
    val cornerPx = with(density) { 30.dp.toPx() }
    val shape = remember(cornerPx) { RoundedRectShape(cornerPx) }

    Box(Modifier.fillMaxSize()) {
        // 被采样的背景必须是独立一层（放在 VividBackdropLayer 里），否则卡片会采样到自己 → 栈溢出
        VividBackdropLayer(backdrop)
        NightStars()
        Column(
            Modifier
                .fillMaxSize()
                .windowInsetsPadding(WindowInsets.statusBars)
                .padding(horizontal = 18.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                Modifier.fillMaxWidth().cardEnter(0),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    "ExtractKit",
                    fontSize = 32.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = pal.ink,
                    modifier = Modifier.weight(1f),
                )
                ThemeSwitch(backdrop = backdrop, onTheme = onTheme)
            }

            GlassRow(
                modifier = Modifier.cardEnter(1),
                backdrop = backdrop, shape = shape,
                title = banner.title,
                value = banner.sub,
                // 提示色（深琥珀）在夜色底色上偏暗，按主题往亮一档插值
                accent = androidx.compose.ui.graphics.lerp(
                    Color(banner.accent),
                    Color(0xFFF8D48A),
                    EkTheme.mixCoarse,
                ),
                onClick = onBanner,
            )

            GlassGroup(backdrop, shape, modifier = Modifier.cardEnter(2)) {
                Row2("设备", device); Row2("内核", kernel)
                ClickRow("内核适配", adaptLabel, onKernel, divider = false)
            }
            GlassGroup(backdrop, shape, modifier = Modifier.cardEnter(3)) {
                ClickRow("执行链路", backendLabel, onBackend)
                ClickRow("标定", "导入本机固件包，解析偏移", onCalib)
                SafeModeRow(backdrop, safeMode, onSafeMode)
                ClickRow("根管理器", manager, onManager)
                ClickRow("支持开发", "您的细微打赏 都是对开发者的支持", onSupport, divider = false)
            }

            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                // 一左一右相向而来，碰一下再弹开：胶囊从左边、日志钮从右边
                Box(Modifier.collideEnter(fromLeft = true)) {
                    // 9.425：回到上游 —— armed 之后退出就是 panic 的来源，所以运行中不可停，只显示状态。
                    GlassPill(if (busy) "执行中…" else "开始提权", backdrop, shape, if (busy) ({}) else onRun)
                }
                Spacer(Modifier.width(10.dp))
                Box(Modifier.collideEnter(fromLeft = false)) {
                    GlassLogButton(backdrop, shape, onLog)
                }
            }
        }
    }
}

@Composable
internal fun Modifier.glass(backdrop: com.kyant.backdrop.Backdrop, shape: com.kyant.shapes.RoundedRectangularShape): Modifier =
    this.drawBackdrop(
        backdrop = backdrop,
        shape = { shape },
        effects = {
            vibrancy()
            blur(2.dp.toPx())
            lens(12.dp.toPx(), 24.dp.toPx())
        },
        highlight = { Highlight.Default.copy(alpha = if (EkTheme.dark) 0.20f else 0.32f) },
        shadow = { Shadow.Default },
        innerShadow = { InnerShadow.Default },
        onDrawSurface = { drawRect(paletteFor(EkTheme.mixCoarse).glass) },
    )

@Composable
private fun GlassGroup(
    backdrop: com.kyant.backdrop.Backdrop,
    shape: com.kyant.shapes.RoundedRectangularShape,
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(
        modifier
            .fillMaxWidth()
            .glass(backdrop, shape)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
        content = content,
    )
}

@Composable
private fun GlassRow(
    backdrop: com.kyant.backdrop.Backdrop,
    shape: com.kyant.shapes.RoundedRectangularShape,
    title: String,
    value: String,
    accent: Color,
    onClick: (() -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier
            .fillMaxWidth()
            .glass(backdrop, shape)
            .then(if (onClick != null) Modifier.clickable { onClick() } else Modifier)
            .padding(horizontal = 20.dp, vertical = 18.dp),
    ) {
        Text(title, fontSize = 22.sp, fontWeight = FontWeight.SemiBold, color = paletteFor(EkTheme.mixCoarse).ink)
        Spacer(Modifier.height(4.dp))
        Text(value, fontSize = 14.sp, color = accent)
    }
}

@Composable
private fun ColumnScope.Row2(k: String, v: String) {
    Column {
        Text(k, fontSize = 17.sp, fontWeight = FontWeight.SemiBold, color = paletteFor(EkTheme.mixCoarse).ink)
        Text(v, fontSize = 13.5.sp, color = paletteFor(EkTheme.mixCoarse).sub)
    }
}

@Composable
private fun ColumnScope.ClickRow(
    k: String,
    v: String,
    onClick: () -> Unit,
    hint: String? = null,
    divider: Boolean = true,
) {
    androidx.compose.foundation.layout.Row(
        Modifier.fillMaxWidth().glassClickable(onClick),
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(k, fontSize = 17.sp, fontWeight = FontWeight.SemiBold, color = paletteFor(EkTheme.mixCoarse).ink)
            if (v.isNotBlank()) Text(v, fontSize = 13.5.sp, color = paletteFor(EkTheme.mixCoarse).sub)
        }
        if (hint != null) Text(hint, fontSize = 12.5.sp, color = paletteFor(EkTheme.mixCoarse).faint)
        Text("›", fontSize = 18.sp, color = paletteFor(EkTheme.mixCoarse).chevron)
    }
    if (divider) {
        androidx.compose.foundation.layout.Box(
            Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(paletteFor(EkTheme.mixCoarse).divider)
        )
    }
}

/** 安全模式：加载前把已有模块临时 disable，交接完成后再放开。 */
@Composable
private fun ColumnScope.SafeModeRow(
    backdrop: com.kyant.backdrop.Backdrop,
    on: Boolean,
    onChange: (Boolean) -> Unit,
) {
    androidx.compose.foundation.layout.Row(
        Modifier.fillMaxWidth(),
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text("安全模式", fontSize = 17.sp, fontWeight = FontWeight.SemiBold, color = paletteFor(EkTheme.mixCoarse).ink)
            Text(
                if (on) "加载前临时禁用已有模块" else "已有模块保持启用",
                fontSize = 13.5.sp,
                color = paletteFor(EkTheme.mixCoarse).sub,
                maxLines = 1,
            )
        }
        SafeToggle(backdrop, on, onChange)
    }
    androidx.compose.foundation.layout.Box(
        Modifier
            .fillMaxWidth()
            .height(1.dp)
            .background(paletteFor(EkTheme.mixCoarse).divider)
    )
}

/** 开关：玻璃胶囊轨道 + 玻璃圆钮 —— 轨道把背景取景进来染一点绿，钮是颗小透镜。 */
@Composable
private fun SafeToggle(backdrop: com.kyant.backdrop.Backdrop, on: Boolean, onChange: (Boolean) -> Unit) {
    val t by androidx.compose.animation.core.animateFloatAsState(
        targetValue = if (on) 1f else 0f,
        animationSpec = androidx.compose.animation.core.spring(
            dampingRatio = 0.62f,
            stiffness = 900f,
        ),
        label = "safeToggle",
    )
    val trackW = 56.dp
    val trackH = 32.dp
    val knob = 26.dp
    val pad = 3.dp
    val capsule = remember { com.kyant.shapes.CapsuleShape() }
    Box(
        Modifier
            .size(trackW, trackH)
            .glassTrack(backdrop, capsule, t)
            .clickable(onClick = { onChange(!on) }),
        contentAlignment = Alignment.CenterStart,
    ) {
        Box(
            Modifier
                .padding(horizontal = pad)
                .offset(x = (trackW - knob - pad * 2) * t)
                .size(knob)
                .glassKnob(backdrop, capsule)
        )
    }
}

/** 开关轨道：玻璃胶囊，开的时候往绿上染，关的时候是淡白玻璃。 */
@Composable
private fun Modifier.glassTrack(
    backdrop: com.kyant.backdrop.Backdrop,
    shape: com.kyant.shapes.RoundedRectangularShape,
    t: Float,
): Modifier = this.drawBackdrop(
    backdrop = backdrop,
    shape = { shape },
    effects = {
        vibrancy()
        blur(4.dp.toPx())
        lens(9.dp.toPx(), 10.dp.toPx())
    },
    highlight = { Highlight.Default.copy(alpha = if (EkTheme.dark) 0.22f else 0.30f) },
    shadow = { Shadow.Default },
    innerShadow = { InnerShadow.Default },
    onDrawSurface = {
        val base = if (EkTheme.dark) Color.White.copy(alpha = 0.12f) else Color.White.copy(alpha = 0.18f)
        val green = Color(0xFF35C46A).copy(alpha = if (EkTheme.dark) 0.45f else 0.55f)
        drawRect(androidx.compose.ui.graphics.lerp(base, green, t))
    },
)

/** 开关上的玻璃钮：小透镜 + 淡淡的白，边缘透出背景色。 */
@Composable
private fun Modifier.glassKnob(
    backdrop: com.kyant.backdrop.Backdrop,
    shape: com.kyant.shapes.RoundedRectangularShape,
): Modifier = this.drawBackdrop(
    backdrop = backdrop,
    shape = { shape },
    effects = {
        vibrancy()
        blur(2.dp.toPx())
        lens(7.dp.toPx(), 6.dp.toPx())
    },
    highlight = { Highlight.Default.copy(alpha = 0.55f) },
    shadow = { Shadow.Default },
    innerShadow = { InnerShadow.Default },
    onDrawSurface = { drawRect(Color.White.copy(alpha = if (EkTheme.dark) 0.78f else 0.92f)) },
)

/** 首页卡片依次从下往上「浮」进来：每个元素错开 70ms。 */
/** 底部两颗：一左一右撞过来，碰一下再各自弹回原位。 */
@Composable
private fun Modifier.collideEnter(fromLeft: Boolean): Modifier {
    var shown by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        kotlinx.coroutines.delay(210L)
        shown = true
    }
    val travel = 118f
    // 弹簧而不是关键帧：落在终点时会自己回弹一下，才有"撞上弹开"的手感
    val dx by androidx.compose.animation.core.animateFloatAsState(
        targetValue = if (shown) 0f else if (fromLeft) -travel else travel,
        animationSpec = androidx.compose.animation.core.spring(
            dampingRatio = 0.52f,
            stiffness = 620f,
            visibilityThreshold = 0.4f,
        ),
        label = if (fromLeft) "pillDx" else "logDx",
    )
    val alpha by androidx.compose.animation.core.animateFloatAsState(
        targetValue = if (shown) 1f else 0f,
        animationSpec = androidx.compose.animation.core.tween(150),
        label = if (fromLeft) "pillA" else "logA",
    )
    // 撞上那一下轻微压扁 + 回弹，靠 delay 对齐弹簧到位的时间
    val squash by androidx.compose.animation.core.animateFloatAsState(
        targetValue = if (shown) 1f else 1f,
        animationSpec = androidx.compose.animation.core.keyframes {
            durationMillis = 560
            1f at 0
            0.95f at 300
            1.02f at 380
            1f at 560
        },
        label = if (fromLeft) "pillS" else "logS",
    )
    return this.graphicsLayer {
        translationX = dx.dp.toPx()
        this.alpha = alpha
        scaleX = squash
        scaleY = squash
    }
}

@Composable
private fun Modifier.cardEnter(index: Int): Modifier {
    var shown by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        kotlinx.coroutines.delay(index * 62L)
        shown = true
    }
    val alpha by androidx.compose.animation.core.animateFloatAsState(
        targetValue = if (shown) 1f else 0f,
        animationSpec = androidx.compose.animation.core.tween(305, easing = androidx.compose.animation.core.FastOutSlowInEasing),
        label = "alpha$index",
    )
    val dy by androidx.compose.animation.core.animateDpAsState(
        targetValue = if (shown) 0.dp else 22.dp,
        animationSpec = androidx.compose.animation.core.tween(330, easing = androidx.compose.animation.core.FastOutSlowInEasing),
        label = "dy$index",
    )
    return this.graphicsLayer {
        this.alpha = alpha
        translationY = dy.toPx()
        val sc = 1f - (dy.value / 22f) * 0.02f
        scaleX = sc
        scaleY = sc
    }
}

/** 圆形玻璃按钮：中间画一个「日志」图标（文档 + 三行横线）。 */
@Composable
private fun GlassLogButton(
    backdrop: com.kyant.backdrop.Backdrop,
    shape: com.kyant.shapes.RoundedRectangularShape,
    onClick: () -> Unit,
) {
    val circle = remember { com.kyant.shapes.CapsuleShape() }
    Box(
        Modifier
            .size(56.dp)
            .glassClickable(onClick)
            .drawBackdrop(
                backdrop = backdrop,
                shape = { circle },
                effects = {
                    vibrancy()
                    blur(2.dp.toPx())
                    lens(10.dp.toPx(), 20.dp.toPx())
                },
                highlight = { Highlight.Default.copy(alpha = if (EkTheme.dark) 0.20f else 0.32f) },
                shadow = { Shadow.Default },
                innerShadow = { InnerShadow.Default },
                onDrawSurface = { drawRect(paletteFor(EkTheme.mixCoarse).glassSoft) },
            ),
        contentAlignment = Alignment.Center,
    ) {
        Canvas(Modifier.size(22.dp)) {
            val ink = paletteFor(EkTheme.mixCoarse).ink
            val w = size.width
            val h = size.height
            val stroke = w * 0.09f
            // 文档外框
            drawRoundRect(
                color = ink,
                topLeft = Offset(0f, 0f),
                size = Size(w, h),
                cornerRadius = CornerRadius(w * 0.16f, w * 0.16f),
                style = Stroke(width = stroke),
            )
            // 三行文字
            val left = w * 0.22f
            listOf(0.32f, 0.5f, 0.68f).forEachIndexed { i, fy ->
                val right = if (i == 2) w * 0.62f else w * 0.78f
                drawLine(
                    color = ink,
                    start = Offset(left, h * fy),
                    end = Offset(right, h * fy),
                    strokeWidth = stroke * 0.9f,
                    cap = StrokeCap.Round,
                )
            }
        }
    }
}

/**
 * 缓慢流动的色带 + 三个漂移光斑。phase 走 0..1 一个循环，
 * 玻璃卡片每帧重新采样背景，所以能看出颜色在玻璃里慢慢游动。
 */
/** 伪随机：同一个 i 永远落在同一个位置，只有相位在动。 */
private fun hash01(i: Int, k: Float): Float {
    val v = kotlin.math.sin(i * k) * 43758.5453f
    return v - kotlin.math.floor(v)
}

// 水印画笔：每帧都会画，抽出复用，避免 60fps 里反复 new
private val watermarkPaint by lazy {
    android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG).apply {
    color = 0x47FFFFFF
    typeface = android.graphics.Typeface.create("serif", android.graphics.Typeface.BOLD)
    textAlign = android.graphics.Paint.Align.CENTER
    letterSpacing = 0.08f
    maskFilter = android.graphics.BlurMaskFilter(15f, android.graphics.BlurMaskFilter.Blur.NORMAL)
}
}

private var vividArtDay: androidx.compose.ui.graphics.ImageBitmap? = null
private var vividArtNight: androidx.compose.ui.graphics.ImageBitmap? = null
private var vividArtKey = -1

/** 把整幅背景一次性画进位图：逐帧只剩一次纹理搬运，填充率骤降。 */
private fun vividBackdropArt(
    w: Int,
    h: Int,
    dark: Boolean,
    density: androidx.compose.ui.unit.Density,
    layoutDirection: androidx.compose.ui.unit.LayoutDirection,
): androidx.compose.ui.graphics.ImageBitmap {
    val img = androidx.compose.ui.graphics.ImageBitmap(w, h)
    val canvas = androidx.compose.ui.graphics.Canvas(img)
    androidx.compose.ui.graphics.drawscope.CanvasDrawScope().draw(
        density = density,
        layoutDirection = layoutDirection,
        canvas = canvas,
        size = androidx.compose.ui.geometry.Size(w.toFloat(), h.toFloat()),
    ) {
        drawVividBackdrop(phase = 0f, dark = dark, watermarkAlpha = 0f)
    }
    return img
}

/** 逐帧搬运烘焙好的背景：缓慢平移 + 呼吸缩放，等价于原来的漂移，但只搬一次纹理。 */
private fun DrawScope.drawVividBackdropArt(dark: Boolean, phase: Float) {
    val w = size.width.toInt().coerceAtLeast(1)
    val h = size.height.toInt().coerceAtLeast(1)
    val key = w * 31 + h
    if (vividArtKey != key) {
        vividArtDay = vividBackdropArt(w, h, false, this, layoutDirection)
        vividArtNight = vividBackdropArt(w, h, true, this, layoutDirection)
        vividArtKey = key
    }
    val art = (if (dark) vividArtNight else vividArtDay) ?: return
    val a = phase * 2f * Math.PI.toFloat()
    val dx = kotlin.math.sin(a) * size.width * 0.020f
    val dy = kotlin.math.cos(a * 0.8f) * size.height * 0.012f
    val sc = 1.05f + 0.012f * kotlin.math.sin(a * 1.3f)
    withTransform({
        scale(sc, sc, pivot = center)
        translate(dx, dy)
    }) {
        drawImage(art, filterQuality = androidx.compose.ui.graphics.FilterQuality.Low)
    }
}

internal fun DrawScope.drawVividBackdrop(
    phase: Float = 0f,
    dark: Boolean = false,
    watermarkAlpha: Float = 1f,
) {
    val t = phase * 2f * Math.PI.toFloat()

    fun blob(x: Float, y: Float, r: Float, color: Color, drift: Float, ang: Float) {
        val a = t + ang
        val cx = size.width * (x + drift * kotlin.math.cos(a))
        val cy = size.height * (y + drift * 0.7f * kotlin.math.sin(a * 0.8f))
        val radius = size.width * r * (1f + 0.06f * kotlin.math.sin(a * 1.3f))
        drawCircle(
            Brush.radialGradient(listOf(color, color.copy(alpha = 0f)), center = Offset(cx, cy), radius = radius),
            radius = radius,
            center = Offset(cx, cy),
        )
    }

    val w1 = (0.5f + 0.5f * kotlin.math.sin(t)).toFloat()
    val w2 = (0.5f + 0.5f * kotlin.math.sin(t + 2.1f)).toFloat()

    if (!dark) {
        // 白天：底色本身就换色，青绿 ↔ 湖蓝 ↔ 紫，12 秒一轮
        val c0 = androidx.compose.ui.graphics.lerp(Color(0xFFA9EFD6), Color(0xFFCDE8FF), w1)
        val c1 = androidx.compose.ui.graphics.lerp(Color(0xFF9FC3FF), Color(0xFFD9C6FF), w2)
        val c2 = androidx.compose.ui.graphics.lerp(Color(0xFFCBBFFA), Color(0xFF9FE7F2), w1)
        drawRect(
            Brush.linearGradient(
                0f to c0, 0.5f to c1, 1f to c2,
                start = Offset(size.width * (0.1f * kotlin.math.sin(t)), 0f),
                end = Offset(size.width * (1f - 0.1f * kotlin.math.sin(t)), size.height),
            )
        )

        // 三个光斑大范围漂移，半径也跟着呼吸
        blob(0.20f, 0.15f, 0.90f, Color(0x66FFF3D0), 0.16f, 0f)
        blob(0.90f, 0.85f, 0.80f, Color(0x4DFFC3E4), 0.18f, 2.4f)
        blob(0.55f, 0.50f, 0.70f, Color(0x40B9A8FF), 0.14f, 4.4f)
    } else {
        // ---------------- 夜晚主题背景 ----------------
        // 底色：近黑的夜空，从冷蓝黑压到紫黑，随 phase 缓慢换色
        val top = androidx.compose.ui.graphics.lerp(Color(0xFF04050C), Color(0xFF080A1A), w1)
        val mid = androidx.compose.ui.graphics.lerp(Color(0xFF090C1C), Color(0xFF111026), w2)
        val bot = androidx.compose.ui.graphics.lerp(Color(0xFF171129), Color(0xFF0A0F22), w1)
        drawRect(Brush.verticalGradient(0f to top, 0.55f to mid, 1f to bot))

        // 月亮：右上角一团冷光，不画实体月牙 —— 整层要过 28f 模糊，实体会被糊掉
        blob(0.86f, 0.06f, 0.80f, Color(0x4D4A63C8), 0.04f, 0.6f)
        // 三团缓慢漂移的极光：靛蓝 / 紫 / 青
        blob(0.14f, 0.82f, 0.95f, Color(0x3D2E4FD8), 0.13f, 0f)
        blob(0.94f, 0.58f, 0.78f, Color(0x339B5BFF), 0.15f, 2.4f)
        blob(0.46f, 0.26f, 0.72f, Color(0x2A1FBFC8), 0.11f, 4.4f)

        // 星点：位置固定（三角函数当伪随机），一颗一颗错开着呼吸
        for (i in 0 until 64) {
            val fx = hash01(i, 12.9898f)
            val fy = hash01(i, 78.233f) * 0.86f
            val rr = size.width * (0.0008f + 0.0012f * hash01(i, 3.31f))
            val tw = 0.5f + 0.5f * kotlin.math.sin(t * 1.7f + i * 1.13f)
            drawCircle(
                Color.White.copy(alpha = 0.10f + 0.38f * tw),
                radius = rr,
                center = Offset(size.width * fx, size.height * fy),
            )
        }

        // 地平线：底部一层极淡的冷光，画面不悬空
        // 用整幅高度画、把零点写在 0.60 的色标上：
        // 之前用 `drawRect(brush, topLeft = 0.6h, size = 0.4h)` 时，渐变按整层高度解析，
        // 到 0.6h 处已经是 60% 的强度，被 rect 裁出一条横贯全屏的硬边 —— 就是"背景被隔断"。
        drawRect(
            Brush.verticalGradient(
                0f to Color(0x00000000),
                0.60f to Color(0x00000000),
                1f to Color(0x332B4A9E),
            )
        )
    }

}

/**
 * 大字水印「酷安璃do」。
 *
 * 原来每帧用 Paint + BlurMaskFilter(22f) 直接 drawText —— 带毛边的字每帧重描一遍字形，
 * 白天主题里每 200 ms 背景换档就卡一下。现在把两层字**烘成一张位图**（每帧只剩一次
 * 带旋转的 drawImage），位置/角度/明暗仍由 phase 驱动，看得到的流动感一点没少。
 */
internal fun DrawScope.drawWatermark(phase: Float, alpha: Float) {
    if (alpha <= 0.01f) return
    val t = phase * 2f * Math.PI.toFloat()
    val art = watermarkArt(size.width.toInt()) ?: return
    val wx = size.width * (0.50f + 0.07f * kotlin.math.sin(t * 1.1f))
    val wy = size.height * (0.40f + 0.05f * kotlin.math.cos(t * 0.9f))
    val wRot = -11f + 5f * kotlin.math.sin(t * 0.7f)
    val pulse = 0x52 + 0x26 * (0.5f + 0.5f * kotlin.math.sin(t * 1.3f))
    val a = (pulse / 255f * alpha).coerceIn(0f, 1f)
    if (a <= 0.004f) return
    withTransform({ rotate(degrees = wRot, pivot = Offset(wx, wy)) }) {
        drawImage(
            image = art.image,
            dstOffset = androidx.compose.ui.unit.IntOffset(
                (wx - art.anchorX).toInt(),
                (wy - art.anchorY).toInt(),
            ),
            alpha = a,
            filterQuality = androidx.compose.ui.graphics.FilterQuality.Low,
        )
    }
}

private class WatermarkArt(
    val image: androidx.compose.ui.graphics.ImageBitmap,
    val anchorX: Float,
    val anchorY: Float,
)

private var wmArtCache: WatermarkArt? = null
private var wmArtWidth = 0

/** 把两层水印字（含 22f 毛边）烘成一张 ARGB 位图，按宽度缓存。 */
private fun watermarkArt(width: Int): WatermarkArt? {
    if (width <= 0) return null
    wmArtCache?.let { if (wmArtWidth == width) return it }
    val w = width.toFloat()
    val text = "酷安璃do"
    val size1 = w * 0.34f
    val size2 = size1 * 0.62f
    val paint = watermarkPaint
    paint.textSize = size1
    val m1 = paint.measureText(text)
    val a1 = paint.fontMetrics.ascent
    val d1 = paint.fontMetrics.descent
    paint.textSize = size2
    val m2 = paint.measureText(text)
    val a2 = paint.fontMetrics.ascent
    val d2 = paint.fontMetrics.descent
    val dx2 = w * 0.05f
    val dy2 = size1 * 0.72f
    val pad = 34f
    val left = minOf(-m1 / 2f, dx2 - m2 / 2f) - pad
    val right = maxOf(m1 / 2f, dx2 + m2 / 2f) + pad
    val top = minOf(a1, dy2 + a2) - pad
    val bottom = maxOf(d1, dy2 + d2) + pad
    val bw = (right - left).toInt().coerceAtLeast(1)
    val bh = (bottom - top).toInt().coerceAtLeast(1)
    if ((bw.toLong() * bh) > 40_000_000L) return null
    val art = runCatching {
        val bmp = android.graphics.Bitmap.createBitmap(bw, bh, android.graphics.Bitmap.Config.ARGB_8888)
        val canvas = android.graphics.Canvas(bmp)
        canvas.translate(-left, -top)
        paint.textSize = size1
        paint.color = 0xFFFFFFFF.toInt()
        canvas.drawText(text, 0f, 0f, paint)
        paint.textSize = size2
        paint.color = 0xAAFFFFFF.toInt()
        canvas.drawText(text, dx2, dy2, paint)
        WatermarkArt(bmp.asImageBitmap(), -left, -top)
    }.getOrNull() ?: return null
    wmArtCache = art
    wmArtWidth = width
    return art
}

@Composable
private fun GlassPill(
    label: String,
    backdrop: com.kyant.backdrop.Backdrop,
    shape: com.kyant.shapes.RoundedRectangularShape,
    onClick: (() -> Unit)?,
) {
    Box(
        Modifier
            .fillMaxWidth(0.66f)
            .height(56.dp)
            .then(if (onClick != null) Modifier.glassClickable(onClick) else Modifier)
            .drawBackdrop(
                backdrop = backdrop,
                shape = { shape },
                effects = {
                    vibrancy()
                    blur(2.dp.toPx())
                    lens(12.dp.toPx(), 24.dp.toPx())
                },
                highlight = { Highlight.Default.copy(alpha = if (EkTheme.dark) 0.20f else 0.32f) },
                shadow = { Shadow.Default },
                innerShadow = { InnerShadow.Default },
                // 透明玻璃：只叠一层很淡的白，主色交给背景本身
                onDrawSurface = { drawRect(paletteFor(EkTheme.mixCoarse).glassSoft) },
            ),
        contentAlignment = Alignment.Center,
    ) {
        Text(label, color = paletteFor(EkTheme.mixCoarse).ink, fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
    }
}

/**
 * 右上角主题开关：真玻璃 —— 直接把背景层取景进来做模糊 + 折射 + 高光，
 * 滑块是一颗同样取景的玻璃珠，太阳 / 月亮谁被选中谁点亮。
 */
/**
 * 右上角主题开关：按 bottom tabs 的样子做 —— 一条玻璃胶囊装两格，
 * 选中的那格浮起一块内嵌玻璃片（内阴影 + 高光边），太阳 / 月亮谁选中谁点亮。
 */
@Composable
private fun ThemeSwitch(backdrop: com.kyant.backdrop.Backdrop, onTheme: () -> Unit) {
    // dark 只在这里读：开关自己重组，不牵动整页
    val dark = EkTheme.dark
    val pal = paletteFor(EkTheme.mixCoarse)
    val t by androidx.compose.animation.core.animateFloatAsState(
        targetValue = if (dark) 1f else 0f,
        animationSpec = androidx.compose.animation.core.spring(
            dampingRatio = 0.72f,
            stiffness = 620f,
        ),
        label = "themeTab",
    )
    val w = 78.dp
    val h = 38.dp
    val pad = 3.dp
    val segW = (w - pad * 2) / 2f
    val capsule = remember { com.kyant.shapes.CapsuleShape() }
    Box(
        Modifier
            .size(w, h)
            .glassSwitch(backdrop, capsule)
            .clickable(onClick = onTheme),
        contentAlignment = Alignment.CenterStart,
    ) {
        Box(
            Modifier
                .align(Alignment.CenterStart)
                .offset(x = pad + segW * t)
                .size(segW, h - pad * 2)
                .glassTab(backdrop, capsule)
        )
        Row(Modifier.fillMaxSize().padding(horizontal = pad)) {
            Box(Modifier.weight(1f).fillMaxHeight(), contentAlignment = Alignment.Center) {
                SunMark(active = !dark, lit = Color(0xFFF0A020), dim = pal.chevron)
            }
            Box(Modifier.weight(1f).fillMaxHeight(), contentAlignment = Alignment.Center) {
                MoonMark(active = dark, lit = Color(0xFF6E7BFF), dim = pal.chevron)
            }
        }
    }
}

/** 开关外壳的玻璃：比卡片再清透一点、折射更明显，才看得出是“液态”。 */
@Composable
private fun Modifier.glassSwitch(
    backdrop: com.kyant.backdrop.Backdrop,
    shape: com.kyant.shapes.RoundedRectangularShape,
): Modifier = this.drawBackdrop(
    backdrop = backdrop,
    shape = { shape },
    effects = {
        vibrancy()
        blur(6.dp.toPx())
        lens(11.dp.toPx(), 18.dp.toPx())
    },
    highlight = { Highlight.Default.copy(alpha = if (EkTheme.dark) 0.24f else 0.34f) },
    shadow = { Shadow.Default },
    innerShadow = { InnerShadow.Default },
    onDrawSurface = { drawRect(Color.White.copy(alpha = if (EkTheme.dark) 0.10f else 0.26f)) },
)

/** 选中格那块内嵌玻璃片：小半径透镜 + 更强的内阴影，才看得出是浮起的一格。 */
@Composable
private fun Modifier.glassTab(
    backdrop: com.kyant.backdrop.Backdrop,
    shape: com.kyant.shapes.RoundedRectangularShape,
): Modifier = this.drawBackdrop(
    backdrop = backdrop,
    shape = { shape },
    effects = {
        vibrancy()
        blur(2.dp.toPx())
        lens(10.dp.toPx(), 9.dp.toPx())
    },
    highlight = { Highlight.Default.copy(alpha = if (EkTheme.dark) 0.26f else 0.38f) },
    shadow = { Shadow.Default },
    innerShadow = { InnerShadow.Default },
    onDrawSurface = { drawRect(Color.White.copy(alpha = if (EkTheme.dark) 0.16f else 0.46f)) },
)

/** 太阳：圆心 + 八条射线。 */
@Composable
private fun SunMark(active: Boolean, lit: Color, dim: Color) {
    val c = if (active) lit else dim
    Canvas(Modifier.size(17.dp)) {
        val r = size.minDimension / 2f
        val core = r * 0.44f
        drawCircle(c, core, center)
        val sw = r * 0.15f
        for (i in 0 until 8) {
            val a = (i * 45f) * (Math.PI / 180.0).toFloat()
            val cs = kotlin.math.cos(a)
            val sn = kotlin.math.sin(a)
            drawLine(
                color = c,
                start = Offset(center.x + cs * core * 1.62f, center.y + sn * core * 1.62f),
                end = Offset(center.x + cs * r * 0.96f, center.y + sn * r * 0.96f),
                strokeWidth = sw,
                cap = StrokeCap.Round,
            )
        }
    }
}

/** 月亮：圆挖掉一块，剩下的就是月牙。 */
@Composable
private fun MoonMark(active: Boolean, lit: Color, dim: Color) {
    val c = if (active) lit else dim
    Canvas(Modifier.size(17.dp)) {
        val d = size.minDimension
        val outer = androidx.compose.ui.geometry.Rect(
            Offset(d * 0.04f, d * 0.04f),
            Size(d * 0.92f, d * 0.92f),
        )
        val hole = androidx.compose.ui.geometry.Rect(
            Offset(d * 0.38f, d * (-0.02f)),
            Size(d * 0.92f, d * 0.92f),
        )
        val moon = androidx.compose.ui.graphics.Path().apply { addOval(outer) }
        val bite = androidx.compose.ui.graphics.Path().apply { addOval(hole) }
        val crescent = androidx.compose.ui.graphics.Path()
        crescent.op(moon, bite, androidx.compose.ui.graphics.PathOperation.Difference)
        drawPath(crescent, c)
    }
}


/**
 * 夜间动态星空：一层独立的小图层，自己慢速漂移 + 呼吸，最后整体过一道极轻的模糊，
 * 看起来是"远处在动的星"，而不是钉在壁纸上的白点。
 * 和时间相关的量都在 draw 里读，靠 derivedStateOf 量化到 1/24 秒，
 * 不触发重组，也不会把 120Hz 的帧预算吃掉。
 */
@Composable
internal fun NightStars(modifier: Modifier = Modifier) {
    val timeState = androidx.compose.animation.core.rememberInfiniteTransition(label = "sky")
        .animateFloat(
            initialValue = 0f,
            targetValue = 1f,
            animationSpec = androidx.compose.animation.core.infiniteRepeatable(
                animation = androidx.compose.animation.core.tween(
                    durationMillis = 120_000,
                    easing = androidx.compose.animation.core.LinearEasing,
                ),
                repeatMode = androidx.compose.animation.core.RepeatMode.Restart,
            ),
            label = "skyTime",
        )
    // 120 秒一轮，量化到 1/24 秒 → 24fps 的肉眼顺滑，够省。
    val tick = androidx.compose.runtime.remember(timeState) {
        androidx.compose.runtime.derivedStateOf { (timeState.value * 120f * 24f).toInt() }
    }
    Box(
        modifier
            .fillMaxSize()
            .drawBehind {
                val a = EkTheme.mix.coerceIn(0f, 1f)
                if (a < 0.015f) return@drawBehind
                val time = tick.value / 24f
                fun frac(v: Float): Float = v - kotlin.math.floor(v)

                // 银河：一条斜着的淡光带，慢慢左右晃
                val tilt = 0.16f * kotlin.math.sin(time * 0.03f)
                drawRect(
                    Brush.linearGradient(
                        0f to Color(0x00000000),
                        0.45f to Color(0xFF2B3A7A).copy(alpha = 0.10f * a),
                        0.62f to Color(0xFF4A3E8E).copy(alpha = 0.08f * a),
                        1f to Color(0x00000000),
                        start = Offset(size.width * (0.15f + tilt), 0f),
                        end = Offset(size.width * (0.75f + tilt), size.height),
                    )
                )

                // 星：大小、亮度、漂移速度各不相同，各自呼吸
                for (i in 0 until 150) {
                    val hs = hash01(i, 5.71f)
                    val hx = hash01(i, 12.9898f)
                    val hy = hash01(i, 78.233f)
                    val sp = 0.0006f + 0.0022f * hs
                    val x = frac(hx + time * sp)
                    val y = frac(hy + time * sp * 0.45f)
                    val px = size.width * x
                    val py = size.height * (0.02f + 0.94f * y)
                    val tw = 0.5f + 0.5f * kotlin.math.sin(time * (0.6f + 1.4f * hs) + i * 1.7f)
                    val core = size.width * (0.0006f + 0.0016f * hs * hs)
                    val alpha = (0.10f + 0.58f * tw) * a
                    // 外圈光晕 = 天然的"微模糊"，配上整层 2.5f 的模糊才不刺眼
                    val glow = core * 4.2f
                    // 光晕用两层实心圆代替 radialGradient：一层 150 个 shader 是切换时最大的一笔开销，
                    // 圆边交给整层 2.5f 的模糊去化开，观感差别肉眼几乎看不出。
                    if (glow > 0.5f) {
                        drawCircle(Color(0xFFC6D6FF).copy(alpha = alpha * 0.10f), glow, Offset(px, py))
                        drawCircle(Color(0xFFC6D6FF).copy(alpha = alpha * 0.14f), glow * 0.52f, Offset(px, py))
                    }
                    drawCircle(Color.White.copy(alpha = alpha), core, Offset(px, py))
                }

                // 流星：每 7 秒一颗，斜着划过去，尾巴用渐变收掉
                val mt = frac(time / 7f)
                if (mt < 0.16f) {
                    val k = mt / 0.16f
                    val sx = size.width * (0.92f - 0.55f * k)
                    val sy = size.height * (0.06f + 0.30f * k)
                    val len = size.width * 0.16f
                    val fade = (1f - k) * a
                    drawLine(
                        brush = Brush.linearGradient(
                            listOf(
                                Color.White.copy(alpha = 0.55f * fade),
                                Color(0xFF9FB6FF).copy(alpha = 0.26f * fade),
                                Color(0x00000000),
                            ),
                            start = Offset(sx, sy),
                            end = Offset(sx + len, sy - len * 0.54f),
                        ),
                        start = Offset(sx, sy),
                        end = Offset(sx + len, sy - len * 0.54f),
                        strokeWidth = maxOf(1.2f, size.width * 0.0016f),
                        cap = StrokeCap.Round,
                    )
                }
            }
            .graphicsLayer {
                renderEffect = android.graphics.RenderEffect
                    .createBlurEffect(2.5f, 2.5f, android.graphics.Shader.TileMode.CLAMP)
                    .asComposeRenderEffect()
            }
    )
}


/** 当前页面的背景图层，供底部面板取景做玻璃（由 setContent 提供）。 */
internal val LocalBackdrop =
    androidx.compose.runtime.compositionLocalOf<com.kyant.backdrop.Backdrop?> { null }

/** 只有上两个角是圆的形状：底部面板要贴死屏幕下沿，不能有下圆角。 */
internal class TopRoundedShape(private val radiusPx: Float) : com.kyant.shapes.RoundedRectangularShape {
    override fun corners(
        size: androidx.compose.ui.geometry.Size,
        layoutDirection: androidx.compose.ui.unit.LayoutDirection,
        density: androidx.compose.ui.unit.Density,
    ): com.kyant.shapes.Corners {
        val v = radiusPx.coerceAtMost(size.minDimension / 2f)
        return com.kyant.shapes.Corners(v, v, 0f, 0f)
    }

    override fun createOutline(
        size: androidx.compose.ui.geometry.Size,
        layoutDirection: androidx.compose.ui.unit.LayoutDirection,
        density: androidx.compose.ui.unit.Density,
    ): androidx.compose.ui.graphics.Outline {
        val v = radiusPx.coerceAtMost(size.minDimension / 2f)
        return androidx.compose.ui.graphics.Outline.Generic(
            Path().apply {
                addRoundRect(
                    androidx.compose.ui.geometry.RoundRect(
                        left = 0f, top = 0f, right = size.width, bottom = size.height,
                        topLeftCornerRadius = androidx.compose.ui.geometry.CornerRadius(v, v),
                        topRightCornerRadius = androidx.compose.ui.geometry.CornerRadius(v, v),
                        bottomRightCornerRadius = androidx.compose.ui.geometry.CornerRadius(0f, 0f),
                        bottomLeftCornerRadius = androidx.compose.ui.geometry.CornerRadius(0f, 0f),
                    )
                )
            }
        )
    }
}

/** 底部面板的玻璃：把页面背景取景进来模糊一遍，再盖一层半透明面板色。 */
@Composable
internal fun Modifier.glassSheet(
    backdrop: com.kyant.backdrop.Backdrop,
    shape: com.kyant.shapes.RoundedRectangularShape,
    night: Boolean,
): Modifier = this.drawBackdrop(
    backdrop = backdrop,
    shape = { shape },
    effects = {
        vibrancy()
        blur(20.dp.toPx())
        lens(6.dp.toPx(), 8.dp.toPx())
    },
    highlight = { Highlight.Default.copy(alpha = if (night) 0.16f else 0.26f) },
    shadow = { Shadow.Default },
    innerShadow = { InnerShadow.Default },
    onDrawSurface = {
        drawRect(
            if (night) Color(0xFF0D1120).copy(alpha = 0.74f)
            else Color.White.copy(alpha = 0.66f)
        )
    },
)

/** 背景层：渐变 + 半模糊 + 供 drawBackdrop 采样。首页与标定页共用。 */
@Composable
internal fun VividBackdropLayer(backdrop: com.kyant.backdrop.backdrops.LayerBackdrop) {
    // 24 秒一轮，慢到不抢注意力，但玻璃里能看出颜色在走
    val phaseState = androidx.compose.animation.core.rememberInfiniteTransition(label = "backdrop")
        .animateFloat(
            initialValue = 0f,
            targetValue = 1f,
            animationSpec = androidx.compose.animation.core.infiniteRepeatable(
                animation = androidx.compose.animation.core.tween(
                    durationMillis = 12_000,
                    easing = androidx.compose.animation.core.LinearEasing,
                ),
                repeatMode = androidx.compose.animation.core.RepeatMode.Restart,
            ),
            label = "phase",
        )
    // 背景漂移不再量化：早先为省满屏模糊把它降到 5 fps，结果漂移本身一顿一顿。
    // 现在满屏模糊已去掉，phase 直接按帧使用（draw 阶段读取，不触发重组）。
    // phase 与主题连续量都在 draw 阶段读取：只在绘制失效里重绘，
    // 不触发重组，切换动画才排得进 120Hz 的帧预算。
    // 复用同一个 Path：揭示圆每帧都在动，别每帧新建对象
    val oval = androidx.compose.runtime.remember { Path() }
    // 白天底图与夜色各录一份绘制命令：只有 phase 换档（约 5 fps）时才重录，
    // 其余帧只是重放记录 —— 切换动画期间不再每帧新建十几个渐变色打着色器。
    val steadyDay = androidx.compose.runtime.remember {
        androidx.compose.runtime.derivedStateOf { EkTheme.mix < 0.02f }
    }
    val reveal = androidx.compose.runtime.remember { RevealCircle() }
    Box(
        Modifier
            .fillMaxSize()
            .layerBackdrop(backdrop)
            .drawBehind {
                val m = EkTheme.mix.coerceIn(0f, 1f)
                drawRect(androidx.compose.ui.graphics.lerp(Color.White, Color(0xFF04050C), m))
            }
    ) {
        Box(
            Modifier
                .fillMaxSize()
                .drawBehind {
                    // 水印单独一层（见下），这里只搬运烘焙好的色带与光斑
                    drawVividBackdropArt(dark = false, phase = phaseState.value)
                },
        )
        // 水印层：位图重放，每帧只有一次带旋转的 drawImage；夜里淡出不画
        Box(
            Modifier
                .fillMaxSize()
                .drawBehind {
                    // 水印随主题连续淡入淡出（原来按 steadyDay 硬切，白天模式切完会「啪」地冒出来）
                    drawWatermark(
                        phase = phaseState.value,
                        alpha = ((0.10f - EkTheme.mix) / 0.10f).coerceIn(0f, 1f),
                    )
                },
        )
        Box(
            Modifier
                .fillMaxSize()
                .graphicsLayer {
                    val m = EkTheme.mix.coerceIn(0f, 1f)
                    val cx = size.width * 0.93f
                    val cy = size.height * 0.055f
                    reveal.cx = cx
                    reveal.cy = cy
                    reveal.radius = kotlin.math.hypot(
                        kotlin.math.max(cx, size.width - cx).toDouble(),
                        kotlin.math.max(cy, size.height - cy).toDouble(),
                    ).toFloat() * m
                    // 永远保持 clip=true：m = 0 时半径 0，裁成空圆什么都不画。
                    // 若在 m=0 时关掉 clip，夜色层会整屏露出来 —— 切回白天一直是黑的。
                    clip = true
                    shape = reveal
                }
                .drawBehind { drawVividBackdropArt(dark = true, phase = phaseState.value) },
        )
    }
}

/** 以右上角主题开关为圆心、半径随主题混合系数生长的揭示圆。 */
internal class RevealCircle : androidx.compose.ui.graphics.Shape {
    var cx = 0f
    var cy = 0f
    var radius = 0f

    override fun createOutline(
        size: androidx.compose.ui.geometry.Size,
        layoutDirection: androidx.compose.ui.unit.LayoutDirection,
        density: androidx.compose.ui.unit.Density,
    ): androidx.compose.ui.graphics.Outline {
        val path = Path()
        path.addOval(Rect(center = Offset(cx, cy), radius = radius.coerceAtLeast(0f)))
        return androidx.compose.ui.graphics.Outline.Generic(path)
    }
}
