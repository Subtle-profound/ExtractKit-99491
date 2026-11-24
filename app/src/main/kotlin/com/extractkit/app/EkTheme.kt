package com.extractkit.app

import android.content.Context
import android.content.res.Configuration
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.Color

/**
 * 全局主题色板：白天 / 夜晚两套，所有界面颜色都从这里取，右上角太阳/月亮一键切换。
 *
 * 只存一个布尔，两套色板是常量表 —— 切换时只重绘，不做动画过渡，
 * 玻璃卡片每帧重采样背景，本身就带上了过渡感。
 */
internal data class EkPalette(
    val night: Boolean,
    /** 主文字 */
    val ink: Color,
    /** 次要文字 */
    val sub: Color,
    /** 提示文字 */
    val faint: Color,
    /** 行尾箭头 */
    val chevron: Color,
    /** 行间分隔线 */
    val divider: Color,
    /** 玻璃卡片表面叠色 */
    val glass: Color,
    /** 更淡的玻璃（圆形按钮、胶囊） */
    val glassSoft: Color,
    /** 面板底色 */
    val card: Color,
    /** 输入框 / 搜索框底 */
    val field: Color,
    /** 列表里的小方块底 */
    val row: Color,
    /** 开关轨道（关） */
    val track: Color,
    /** 开关轨道描边 */
    val trackEdge: Color,
    /** 面板后面的遮罩 */
    val scrim: Color,
    val ok: Color,
    val warn: Color,
    val broken: Color,
    /** 日志正文 */
    val code: Color,
    /** 日志底 */
    val codeBg: Color,
)

private val DAY = EkPalette(
    night = false,
    ink = Color(0xFF111114),
    sub = Color(0xFF6B6B72),
    faint = Color(0xFF8A8A92),
    chevron = Color(0xFF9A9AA2),
    divider = Color(0x0F000000),
    glass = Color(0x47FFFFFF),
    glassSoft = Color(0x2EFFFFFF),
    card = Color(0xFFFBFBFD),
    field = Color(0xFFF1F1F5),
    row = Color(0xFFEDEDF2),
    track = Color(0x14000000),
    trackEdge = Color(0x22000000),
    scrim = Color(0x33000000),
    ok = Color(0xFF12A150),
    warn = Color(0xFFB26A00),
    broken = Color(0xFFB5B5BB),
    code = Color(0xFF2E2E33),
    codeBg = Color(0x08000000),
)

/**
 * 夜晚：近黑底 + 冷月辉光。
 * 图文用带一点蓝的暖白，避免纯白在纯黑上发晕；描边一律用白色低透明度，
 * 这样玻璃卡片叠在夜色上还是一块"亮的玻璃"，不会变成灰补丁。
 */
private val NIGHT = EkPalette(
    night = true,
    ink = Color(0xFFF0F2F9),
    sub = Color(0xFF9EA4B8),
    faint = Color(0xFF878DA1),
    chevron = Color(0xFF7A8094),
    divider = Color(0x1FFFFFFF),
    glass = Color(0x1AFFFFFF),
    glassSoft = Color(0x1FFFFFFF),
    card = Color(0xFF15171F),
    field = Color(0xFF1E2129),
    row = Color(0xFF272B36),
    track = Color(0x24FFFFFF),
    trackEdge = Color(0x33FFFFFF),
    scrim = Color(0x8C05060A),
    ok = Color(0xFF3ED47A),
    warn = Color(0xFFE8A93C),
    broken = Color(0xFF5C6273),
    code = Color(0xFFCBD1E1),
    codeBg = Color(0x14FFFFFF),
)

private fun blend(a: Color, b: Color, t: Float): Color =
    androidx.compose.ui.graphics.lerp(a, b, t)

/**
 * 按混合系数取色板：0 = 纯白天，1 = 纯黑夜。
 * 切换主题时 [EkTheme.mix] 从 0 连续走到 1，所有取色都跟着插值 ——
 * 文字、玻璃叠色、分隔线一起过渡，而不是到点硬切。
 */
internal fun paletteFor(mix: Float): EkPalette {
    if (mix <= 0f) return DAY
    if (mix >= 1f) return NIGHT
    // 量化到 1/64 再缓存：一帧里几十次取色只算一次，插值误差肉眼不可见，
    // 但省掉了每帧几百次 lerp 与对象分配（切换动画的帧时间主要省在这里）。
    val q = kotlin.math.round(mix * 64f) / 64f
    if (q == memoMix) return memoPal
    memoMix = q
    memoPal = blendPalette(q)
    return memoPal
}

private var memoMix = -1f
private var memoPal: EkPalette = DAY

private fun blendPalette(mix: Float): EkPalette {
    return EkPalette(
        night = mix >= 0.5f,
        ink = blend(DAY.ink, NIGHT.ink, mix),
        sub = blend(DAY.sub, NIGHT.sub, mix),
        faint = blend(DAY.faint, NIGHT.faint, mix),
        chevron = blend(DAY.chevron, NIGHT.chevron, mix),
        divider = blend(DAY.divider, NIGHT.divider, mix),
        glass = blend(DAY.glass, NIGHT.glass, mix),
        glassSoft = blend(DAY.glassSoft, NIGHT.glassSoft, mix),
        card = blend(DAY.card, NIGHT.card, mix),
        field = blend(DAY.field, NIGHT.field, mix),
        row = blend(DAY.row, NIGHT.row, mix),
        track = blend(DAY.track, NIGHT.track, mix),
        trackEdge = blend(DAY.trackEdge, NIGHT.trackEdge, mix),
        scrim = blend(DAY.scrim, NIGHT.scrim, mix),
        ok = blend(DAY.ok, NIGHT.ok, mix),
        warn = blend(DAY.warn, NIGHT.warn, mix),
        broken = blend(DAY.broken, NIGHT.broken, mix),
        code = blend(DAY.code, NIGHT.code, mix),
        codeBg = blend(DAY.codeBg, NIGHT.codeBg, mix),
    )
}

internal object EkTheme {

    private const val PREFS = "ui"
    private const val KEY = "night"

    /** 目标主题：true = 夜晚。图标、状态栏用它，判断是即时的。 */
    var dark by mutableStateOf(false)
        private set

    /**
     * 连续混合系数：0 = 白天，1 = 夜晚。
     * 切换时由界面层的动画推向目标值，取色（[paletteFor]）与背景揭示圆都读它。
     */
    var mix by mutableFloatStateOf(0f)

    /**
     * 取色专用的粗档位（1/16 步进）。
     * 文字颜色只能在重组里读：若每个调用点都读每帧变化的 [mix]，一次切换要重组整屏 30 多次，
     * 这就是"刚按下那一刻卡一下"的主因。量化到 16 档后只有 16 次重组，
     * 其余帧全走绘制（揭示圆 / 星空读 [mix]），观感仍是连续的。
     */
    var mixCoarse by mutableFloatStateOf(0f)

    /** 启动时读一次：没存过就跟随系统。 */
    fun load(ctx: Context) {
        val prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        dark = if (prefs.contains(KEY)) {
            prefs.getBoolean(KEY, false)
        } else {
            systemDark(ctx)
        }
        mix = if (dark) 1f else 0f
        mixCoarse = mix
    }

    fun toggle(ctx: Context) {
        dark = !dark
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY, dark).apply()
    }

    private fun systemDark(ctx: Context): Boolean =
        (ctx.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
            Configuration.UI_MODE_NIGHT_YES
}
