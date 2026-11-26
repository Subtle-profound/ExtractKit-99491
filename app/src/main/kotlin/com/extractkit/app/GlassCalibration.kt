package com.extractkit.app

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// 标定页跟首页共用一套主题色
private val Ink: Color
    @Composable get() = paletteFor(EkTheme.mixCoarse).ink
private val Sub: Color
    @Composable get() = paletteFor(EkTheme.mixCoarse).sub
private val Ok: Color
    @Composable get() = paletteFor(EkTheme.mixCoarse).ok
private val Warn: Color
    @Composable get() = paletteFor(EkTheme.mixCoarse).warn
private val CalPal: EkPalette
    @Composable get() = paletteFor(EkTheme.mixCoarse)

@Composable
private fun GlassCard(
    backdrop: com.kyant.backdrop.backdrops.LayerBackdrop,
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    val radius = with(androidx.compose.ui.platform.LocalDensity.current) { 30.dp.toPx() }
    val shape = androidx.compose.runtime.remember(radius) { com.kyant.shapes.RoundedRectShape(radius) }
    Column(
        modifier
            .fillMaxWidth()
            .glass(backdrop, shape)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        content = content,
    )
}

@Composable
private fun Line(
    title: String,
    value: String,
    valueColor: Color = Sub,
    onClick: (() -> Unit)? = null,
    onLongClick: (() -> Unit)? = null,
) {
    Row(
        Modifier
            .fillMaxWidth()
            .then(
                when {
                    onClick != null -> Modifier.glassClickable(onClick, onLongClick)
                    else -> Modifier
                }
            )
            .padding(vertical = 7.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(title, fontSize = 15.5.sp, fontWeight = FontWeight.SemiBold, color = Ink)
            Text(value, fontSize = 13.sp, color = valueColor)
        }
        // 可点击的行统一加 ›，一眼能看出能点
        if (onClick != null) Text("›", fontSize = 18.sp, color = CalPal.chevron)
    }
}

@Composable
internal fun GlassCalibrationScreen(
    backdrop: com.kyant.backdrop.backdrops.LayerBackdrop,
    model: CalibrationModel,
    onBack: () -> Unit,
    onPick: () -> Unit,
    onImport: () -> Unit,
    onSave: () -> Unit,
    onShare: () -> Unit,
) {
    val snack = model.message
    LaunchedEffect(snack) { if (snack != null) model.consumeMessage() }

    // 9.451: 顺序 信息卡 → 环境自检 → 解析日志（吃掉剩余高度、框内滚）→ 保存/导入/分享
    // → 推荐大字。「查询固件包」整条功能已按 m09658 删除，入口不再出现。
    Column(
        Modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.statusBars)
            .padding(horizontal = 16.dp)
            .padding(top = 8.dp, bottom = 14.dp),
    ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("✕", fontSize = 22.sp, color = Sub, modifier = Modifier.clickable { onBack() })
                Spacer(Modifier.width(14.dp))
                Text("标定", fontSize = 26.sp, fontWeight = FontWeight.SemiBold, color = Ink)
                Spacer(Modifier.weight(1f))
                if (model.busy) Text("解析中…", fontSize = 13.sp, color = Sub)
            }
            if (snack != null) {
                Spacer(Modifier.height(6.dp))
                Text(snack, fontSize = 12.5.sp, color = Warn)
            }
            Spacer(Modifier.height(10.dp))

            GlassCard(backdrop) {
                Line("内核", model.kernel, if (model.ready) Ok else Sub)
                Line("BTF（结构体偏移）", model.btfLabel, if (model.btfLabel.startsWith("已")) Ok else Sub)
                Line("符号表（kallsyms）", model.symsLabel, if (model.symsLabel.endsWith("符号")) Ok else Sub)
                Line(
                    "CVE-2026-99491 标定产物",
                    model.wacomLabel,
                    if (model.wacomLabel.startsWith("已")) Ok else Sub,
                )
                Spacer(Modifier.height(4.dp))
                Line(
                    "导入本机固件包",
                    if (model.busy) "解析中…" else "选官方 boot / Image，解析偏移",
                    if (model.busy) Sub else Ok,
                    onClick = if (model.busy) null else onPick,
                )
            }

            if (model.showAdvanced) {
                Spacer(Modifier.height(14.dp))
                GlassCard(backdrop) {
                    Text("高级（call site 手填）", fontSize = 15.5.sp, fontWeight = FontWeight.SemiBold, color = Ink)
                    Spacer(Modifier.height(6.dp))
                    Text("自动推不出来时才需要动，填十六进制", fontSize = 12.sp, color = Sub)
                    val fields = listOf(
                        "timer 返址偏移" to (model.advTimer to "0x94"),
                        "cred 低 21 位" to (model.advCred to "0x38458"),
                        "task 低 21 位" to (model.advTask to "0x1CB240"),
                        "task_struct 字节" to (model.advTaskBytes to "0x12C0"),
                    )
                    fields.forEachIndexed { i, (label, pair) ->
                        OutlinedTextField(
                            value = pair.first.orEmpty(),
                            onValueChange = { v ->
                                model.setAdvanced(
                                    if (i == 0) v else model.advTimer,
                                    if (i == 1) v else model.advCred,
                                    if (i == 2) v else model.advTask,
                                    if (i == 3) v else model.advTaskBytes,
                                )
                            },
                            label = { Text(label, fontSize = 12.sp) },
                            placeholder = { Text(pair.second, fontSize = 12.sp, color = Sub) },
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
                            modifier = Modifier.fillMaxWidth().padding(top = 6.dp),
                        )
                    }
                }
            }

            Spacer(Modifier.height(10.dp))

            GlassCard(backdrop) {
                Line(
                    "环境自检",
                    if (model.probing) "采集中…"
                    else if (!Shell.connected()) "需要 Shizuku 已授权 · 没连不跑"
                    else "本机采集 slab / profile / tracefs，不用连电脑",
                    if (model.probing) Sub else Ok,
                    onClick = if (model.probing) null else ({ model.probeEnv() }),
                )
            }


        Spacer(Modifier.height(10.dp))

        // 解析日志：定高区域，内部滚动（9.447）
        GlassCard(backdrop, Modifier.fillMaxWidth().weight(1f).heightIn(min = 140.dp)) {
            Text("解析日志", fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = Ink)
            Spacer(Modifier.height(6.dp))
            val shown = model.logLines.takeLast(400)
            Box(
                Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .clip(RoundedCornerShape(12.dp))
                    .background(CalPal.codeBg)
                    .padding(horizontal = 10.dp, vertical = 8.dp),
            ) {
                Text(
                    if (shown.isEmpty()) "选一个 boot.img 开始" else shown.joinToString("\n"),
                    fontSize = 11.sp,
                    lineHeight = 15.sp,
                    fontFamily = FontFamily.Monospace,
                    color = CalPal.code,
                    softWrap = true,
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState()),
                )
            }
        }

        Spacer(Modifier.height(10.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                listOf(
                    Triple("保存", model.canSave, onSave),
                    Triple("导入", true, onImport),
                    Triple("分享", model.canShare, onShare),
                ).forEach { (label, enabled, action) ->
                    val r = with(androidx.compose.ui.platform.LocalDensity.current) { 22.dp.toPx() }
                    val shape = androidx.compose.runtime.remember(r) { com.kyant.shapes.RoundedRectShape(r) }
                    Box(
                        Modifier
                            .weight(1f)
                            .height(44.dp)
                            .glass(backdrop, shape)
                            .glassClickable(onClick = action, enabled = enabled),
                        contentAlignment = Alignment.Center,
                    ) { Text(label, fontSize = 14.sp, color = if (enabled) Ok else CalPal.broken) }
                }
            }
    }
}

