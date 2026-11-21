// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.sample.ui

import android.content.Intent
import androidx.activity.ComponentActivity
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.virtprobe.core.model.EnvironmentVerdict
import io.virtprobe.core.model.ModuleSummary
import io.virtprobe.core.model.ProbeReport
import io.virtprobe.core.model.Severity
import io.virtprobe.core.model.SignalCategory
import io.virtprobe.core.model.SignalFinding
import io.virtprobe.core.model.InputNarrative
import io.virtprobe.sdk.VirtProbe
import io.virtprobe.sdk.input.VirtProbeWindowCallback
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private val Paper = Color(0xFFF3F0E8)
private val Ink = Color(0xFF1C211C)
private val Muted = Color(0xFF5E675F)
private val Card = Color(0xFFFFFCF7)
private val Line = Color(0xFFDDD6C8)
private val Good = Color(0xFF1E7A4D)
private val GoodBg = Color(0xFFE7F5EC)
private val Warn = Color(0xFF9A6200)
private val WarnBg = Color(0xFFFFF3DE)
private val Bad = Color(0xFFA33B32)
private val BadBg = Color(0xFFFDEEEC)

@Composable
fun VirtProbeScreen() {
    val context = LocalContext.current
    val activity = context as ComponentActivity
    val scope = rememberCoroutineScope()
    var report by remember { mutableStateOf<ProbeReport?>(null) }
    var scanning by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var anomaliesOnly by remember { mutableStateOf(true) }
    var category by remember { mutableStateOf<SignalCategory?>(null) }
    var trace by remember { mutableStateOf<InputNarrative?>(null) }
    var showJson by remember { mutableStateOf(false) }

    fun rescan() {
        if (scanning) return
        scope.launch {
            scanning = true
            error = null
            try {
                val value = withContext(Dispatchers.IO) { VirtProbe.scan(activity) }
                report = value
            } catch (t: Throwable) {
                error = t.message ?: t.javaClass.simpleName
            } finally {
                scanning = false
            }
        }
    }

    LaunchedEffect(Unit) { rescan() }

    val view = LocalView.current
    DisposableEffect(view) {
        val window = activity.window
        val previous = window.callback
        window.callback = VirtProbeWindowCallback(previous) { trace = it }
        onDispose { window.callback = previous }
    }

    MaterialTheme(colorScheme = lightColorScheme(primary = Good, background = Paper, surface = Card, onBackground = Ink, onSurface = Ink)) {
        Surface(modifier = Modifier.fillMaxSize(), color = Paper) {
            val current = report
            val visible = current?.findings.orEmpty().filter { finding ->
                (category == null || finding.category == category) && (!anomaliesOnly || finding.detected)
            }
            LazyColumn(
                modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                item { Spacer(Modifier.height(12.dp)) }
                item {
                    Text("虚拟环境探针", fontSize = 13.sp, color = Muted, fontWeight = FontWeight.Medium)
                    Text("先看结论，再看是哪一类出了问题", fontSize = 22.sp, fontWeight = FontWeight.SemiBold, color = Ink)
                    Text(
                        "信号是启发式的：未命中不能证明真机，模拟器或 adb 注入也不能证明物理手指。",
                        fontSize = 13.sp,
                        color = Muted,
                    )
                }
                item {
                    ConclusionCard(
                        report = current,
                        scanning = scanning,
                        error = error,
                        onRescan = ::rescan,
                        onExport = { showJson = true },
                    )
                }
                if (current != null) {
                    item {
                        CategoryRow(
                            summaries = current.moduleSummaries,
                            selected = category,
                            onSelect = { category = if (category == it) null else it },
                        )
                    }
                }
                item {
                    FilterRow(
                        anomaliesOnly = anomaliesOnly,
                        anomalyCount = current?.anomalyCount ?: 0,
                        checkCount = current?.checkCount ?: 0,
                        onAnomalies = { anomaliesOnly = true },
                        onAll = { anomaliesOnly = false },
                    )
                }
                item { InputPlayground(trace) }
                if (current != null && visible.isEmpty()) {
                    item { EmptyState(anomaliesOnly) }
                }
                itemsIndexed(visible, key = { index, finding -> "${finding.category.name}:${finding.signalId}:$index" }) { _, finding ->
                    FindingCard(finding)
                }
                item { Spacer(Modifier.height(24.dp)) }
            }
        }
    }

    if (showJson && report != null) {
        JsonDialog(json = report!!.toPrettyJson(), onDismiss = { showJson = false })
    }
}

@Composable
private fun ConclusionCard(
    report: ProbeReport?,
    scanning: Boolean,
    error: String?,
    onRescan: () -> Unit,
    onExport: () -> Unit,
) {
    val tone = report?.verdict.tone()
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(18.dp))
            .background(tone.background)
            .padding(16.dp),
    ) {
        Text("核心结论", color = tone.accent, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(6.dp))
        Text(
            text = when {
                error != null -> "这次扫描没有完成"
                report == null -> "正在采集五维信号"
                else -> report.conclusionTitleZh
            },
            color = Ink,
            fontSize = 22.sp,
            fontWeight = FontWeight.SemiBold,
            lineHeight = 30.sp,
        )
        Spacer(Modifier.height(8.dp))
        Text(
            text = error ?: report?.conclusionSummaryZh ?: "模拟器、容器、虚拟屏、硬件一致性和输入来源会一起汇总。",
            color = Ink,
            fontSize = 14.sp,
            lineHeight = 21.sp,
        )
        if (scanning) {
            Spacer(Modifier.height(12.dp))
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth(), color = tone.accent, trackColor = Color.White.copy(alpha = 0.6f))
        }
        if (report != null) {
            Spacer(Modifier.height(14.dp))
            Row(verticalAlignment = Alignment.Bottom) {
                Text(report.riskScore.toString(), fontSize = 40.sp, fontWeight = FontWeight.Bold, color = tone.accent)
                Spacer(Modifier.width(8.dp))
                Text("综合风险分 · ${report.riskBandZh}", color = Muted, modifier = Modifier.padding(bottom = 8.dp))
            }
            Text(report.scoreBreakdownZh, color = Muted, fontSize = 12.sp)
        }
        Spacer(Modifier.height(14.dp))
        Row {
            Button(
                onClick = onRescan,
                enabled = !scanning,
                colors = ButtonDefaults.buttonColors(containerColor = tone.accent, contentColor = Color.White),
            ) { Text(if (scanning) "扫描中" else "重新扫描") }
            Spacer(Modifier.width(8.dp))
            TextButton(onClick = onExport, enabled = report != null) { Text("导出 JSON") }
        }
    }
}

@Composable
private fun CategoryRow(summaries: List<ModuleSummary>, selected: SignalCategory?, onSelect: (SignalCategory) -> Unit) {
    LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        items(summaries) { summary ->
            val tone = summary.tone()
            val active = selected == summary.category
            Column(
                modifier = Modifier
                    .width(148.dp)
                    .clip(RoundedCornerShape(14.dp))
                    .background(if (active) tone.background else Card)
                    .border(1.dp, if (active) tone.accent else Line, RoundedCornerShape(14.dp))
                    .clickable { onSelect(summary.category) }
                    .padding(12.dp),
            ) {
                Text(summary.category.titleZh, color = Ink, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, maxLines = 2)
                Spacer(Modifier.height(8.dp))
                Text(summary.statusZh, color = tone.accent, fontSize = 13.sp, fontWeight = FontWeight.Medium)
            }
        }
    }
}

@Composable
private fun FilterRow(
    anomaliesOnly: Boolean,
    anomalyCount: Int,
    checkCount: Int,
    onAnomalies: () -> Unit,
    onAll: () -> Unit,
) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        ChoiceChip("仅看异常", anomaliesOnly, onAnomalies)
        Spacer(Modifier.width(8.dp))
        ChoiceChip("全部项目", !anomaliesOnly, onAll)
        Spacer(Modifier.weight(1f))
        Text("$anomalyCount 项异常 / $checkCount 项", color = Muted, fontSize = 12.sp)
    }
}

@Composable
private fun ChoiceChip(label: String, selected: Boolean, onClick: () -> Unit) {
    Text(
        text = label,
        color = if (selected) Color.White else Ink,
        fontSize = 13.sp,
        modifier = Modifier
            .clip(RoundedCornerShape(999.dp))
            .background(if (selected) Ink else Card)
            .border(1.dp, if (selected) Ink else Line, RoundedCornerShape(999.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 8.dp),
    )
}

@Composable
private fun InputPlayground(trace: InputNarrative?) {
    var draft by remember { mutableStateOf("") }
    val tone = if (trace?.suspicious == true) ToneBad else if (trace == null) ToneNeutral else ToneGood
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(Card)
            .border(1.dp, Line, RoundedCornerShape(16.dp))
            .padding(14.dp),
    ) {
        Text("试试这次输入从哪来", fontWeight = FontWeight.SemiBold, color = Ink)
        Text("点页面任意位置、在下面输入一个字，都会立刻给出结论。不需要额外配置。", color = Muted, fontSize = 13.sp)
        Spacer(Modifier.height(10.dp))
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(72.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(Paper)
                .border(1.dp, Line, RoundedCornerShape(12.dp)),
            contentAlignment = Alignment.Center,
        ) {
            Text("在这一带点击或滑动", color = Muted)
        }
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = draft,
            onValueChange = { draft = it },
            modifier = Modifier.fillMaxWidth(),
            placeholder = { Text("在这里打字，查看按键来源") },
            singleLine = true,
        )
        Spacer(Modifier.height(10.dp))
        Text(trace?.verdictZh ?: "还没有输入事件", color = tone.accent, fontWeight = FontWeight.SemiBold)
        if (trace != null) {
            NarrativeBlock("实测事件数据", trace.observedDataZh)
            NarrativeBlock("对照基线（不是证明）", trace.expectedBaselineZh)
            NarrativeBlock("建议", trace.recommendationZh)
        }
    }
}

@Composable
private fun EmptyState(anomaliesOnly: Boolean) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(GoodBg)
            .padding(16.dp),
    ) {
        Text(
            if (anomaliesOnly) "这次没有要优先看的异常项" else "当前筛选下没有检查项",
            color = Good,
            fontWeight = FontWeight.SemiBold,
        )
        Text(
            if (anomaliesOnly) "需要对照每条基线时，切换到「全部项目」。低敏提示仍算异常，会留在这个列表里。" else "换一个维度，或回到仅看异常。",
            color = Ink,
            fontSize = 14.sp,
        )
    }
}

@Composable
private fun FindingCard(finding: SignalFinding) {
    var open by remember(finding.signalId) { mutableStateOf(false) }
    val tone = if (!finding.detected) ToneGood else finding.severity.tone()
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(Card)
            .border(1.dp, Line, RoundedCornerShape(16.dp))
            .padding(14.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                if (finding.detected) finding.severity.labelZh else "正常",
                color = tone.accent,
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier
                    .clip(RoundedCornerShape(999.dp))
                    .background(tone.background)
                    .padding(horizontal = 8.dp, vertical = 3.dp),
            )
            Spacer(Modifier.width(8.dp))
            Text(finding.category.titleZh, color = Muted, fontSize = 12.sp)
        }
        Spacer(Modifier.height(8.dp))
        Text(finding.titleZh, color = Ink, fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
        Text(finding.summaryZh, color = Muted, fontSize = 13.sp)
        NarrativeBlock("检测到的数据", finding.observedDataZh)
        NarrativeBlock("正常应该是什么", finding.expectedBaselineZh)
        NarrativeBlock("处理建议", finding.recommendationZh)
        TextButton(onClick = { open = !open }) {
            Text(if (open) "收起底层原始证据" else "查看底层原始证据")
        }
        if (open) {
            Text(finding.sourceAttribution, color = Muted, fontSize = 12.sp, lineHeight = 18.sp)
            Spacer(Modifier.height(6.dp))
            if (finding.rawEvidence.isEmpty()) {
                Text("这条检查没有额外键值。", color = Muted, fontSize = 12.sp)
            } else {
                finding.rawEvidence.forEach { (key, value) ->
                    Text("$key = ${value.ifBlank { "（空）" }}", fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = Ink)
                }
            }
        }
    }
}

@Composable
private fun NarrativeBlock(label: String, body: String) {
    Column(modifier = Modifier.padding(top = 8.dp)) {
        Text(label, color = Muted, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
        Text(body, color = Ink, fontSize = 14.sp, lineHeight = 20.sp)
    }
}

@Composable
private fun JsonDialog(json: String, onDismiss: () -> Unit) {
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            TextButton(onClick = {
                clipboard.setText(AnnotatedString(json))
                val share = Intent(Intent.ACTION_SEND).apply {
                    type = "application/json"
                    putExtra(Intent.EXTRA_TEXT, json)
                }
                context.startActivity(Intent.createChooser(share, "导出检测报告"))
            }) { Text("复制并分享") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("关闭") } },
        title = { Text("检测报告 JSON") },
        text = {
            Text(
                json,
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                modifier = Modifier.heightIn(max = 420.dp).verticalScroll(rememberScrollState()),
            )
        },
    )
}

private data class Tone(val accent: Color, val background: Color)

private val ToneGood = Tone(Good, GoodBg)
private val ToneWarn = Tone(Warn, WarnBg)
private val ToneBad = Tone(Bad, BadBg)
private val ToneNeutral = Tone(Muted, Paper)

private fun EnvironmentVerdict?.tone(): Tone = when (this) {
    null -> ToneNeutral
    EnvironmentVerdict.REAL_DEVICE -> ToneGood
    EnvironmentVerdict.SUSPICIOUS -> ToneWarn
    EnvironmentVerdict.EMULATOR_OR_VM,
    EnvironmentVerdict.VIRTUAL_CONTAINER,
    EnvironmentVerdict.VIRTUALIZED_ENVIRONMENT,
    -> ToneBad
    EnvironmentVerdict.RUNTIME_CLUE -> ToneWarn
}

private fun ModuleSummary.tone(): Tone = when {
    !enabled -> ToneNeutral
    mediumOrAboveCount > 0 -> ToneBad
    anomalyCount > 0 -> ToneWarn
    else -> ToneGood
}

private fun Severity.tone(): Tone = when (this) {
    Severity.INFO, Severity.LOW, Severity.MEDIUM -> ToneWarn
    Severity.HIGH, Severity.CRITICAL -> ToneBad
}
