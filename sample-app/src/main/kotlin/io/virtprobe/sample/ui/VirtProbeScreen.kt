// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.sample.ui

import android.content.Intent
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.activity.compose.BackHandler
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
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.ime
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.union
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
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
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInWindow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.virtprobe.core.json.ReportJson
import io.virtprobe.core.model.InputNarrative
import io.virtprobe.core.model.ProbeReport
import io.virtprobe.core.model.SignalFinding
import io.virtprobe.sample.input.ProbeGestureService
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
private val Clue = Color(0xFF9A6200)
private val Restricted = Color(0xFF3E5C76)

private enum class Page { Home, Input }

private enum class UiGroup(val label: String) {
    Emulator("模拟器 / 虚拟机"),
    Container("应用内虚拟容器"),
    Display("虚拟屏幕"),
    Hardware("硬件一致性"),
    Input("输入来源"),
    Root("Root 与提权"),
    Hook("Hook 与注入"),
    Debug("调试与自动化"),
    Trust("系统信任"),
}

private enum class RowStatus(val label: String) {
    Clue("发现线索"),
    Clear("未发现线索"),
    Restricted("无法检查"),
    Pending("待检测"),
}

private enum class StatusFilter { All, Clue, Clear, Restricted }

/**
 * 清单状态只解释已有报告，不新增检测。
 * 读不到、被拒绝不是「未发现」。ADB、VPN、代理、无障碍和外设清单本身不是线索。
 */
private fun rowStatus(finding: SignalFinding): RowStatus {
    if (finding.signalId in INFO_ONLY) {
        return if (unreadable(finding)) RowStatus.Restricted else RowStatus.Clear
    }
    if (finding.detected) return RowStatus.Clue
    if (unreadable(finding)) return RowStatus.Restricted
    return RowStatus.Clear
}

private val INFO_ONLY = setOf("rt.net.posture", "in.a11y.enabled", "in.dev.inventory")

private fun unreadable(finding: SignalFinding): Boolean {
    val observed = finding.observedDataZh
    val summary = finding.summaryZh
    val readSucceeded = "读取错误=无" in observed || observed.contains("错误=无")
    if (readSucceeded && listOf("EACCES", "拒绝读取", "未读到", "Permission").none { it in observed }) {
        return false
    }
    if (listOf("EACCES", "拒绝读取", "未读到", "Permission", "不可读").any { it in observed }) return true
    return summary.startsWith("无法检查") || summary.startsWith("没有读到") || summary.startsWith("无法读取")
}

private fun groupOf(finding: SignalFinding): UiGroup = when {
    finding.signalId.startsWith("emu.") -> UiGroup.Emulator
    finding.signalId.startsWith("ctn.") -> UiGroup.Container
    finding.signalId.startsWith("vd.") -> UiGroup.Display
    finding.signalId == "con.boot.state" -> UiGroup.Trust
    finding.signalId.startsWith("con.") -> UiGroup.Hardware
    finding.signalId == "in.auto.packages" || finding.signalId == "in.instrumentation" -> UiGroup.Debug
    finding.signalId.startsWith("in.") -> UiGroup.Input
    finding.signalId == "rt.su.paths" || finding.signalId == "rt.mount.markers" || finding.signalId == "rt.pkg.clue" -> UiGroup.Root
    finding.signalId == "rt.maps.inject" -> UiGroup.Hook
    finding.signalId == "rt.debug.tracer" || finding.signalId == "rt.net.posture" -> UiGroup.Debug
    else -> UiGroup.Trust
}

private fun oneSentence(text: String, limit: Int = 72): String {
    val flat = text.trim().replace('\n', ' ')
    val end = flat.indexOf('。')
    val sentence = if (end in 1 until limit) flat.substring(0, end + 1) else flat
    return if (sentence.length <= limit) sentence else sentence.substring(0, limit).trimEnd() + "…"
}

/** 长证据只留一句，但要带上命中片段，避免只看到默认屏或前半段。 */
private fun briefActual(text: String): String {
    val flat = text.trim().replace('\n', ' ')
    val key = listOf("Overlay", "拒绝读取", "EACCES", "未读到", "qemu", "goldfish", "dev-keys", "非默认")
        .firstOrNull { it in flat }
    if (key == null || flat.length <= 72) return oneSentence(flat)
    val at = flat.indexOf(key)
    val start = flat.lastIndexOf('；', at).let { if (it < 0) (at - 8).coerceAtLeast(0) else it + 1 }
    val slice = flat.substring(start, flat.length).trim()
    return if (slice.length <= 72) slice else slice.substring(0, 72).trimEnd() + "…"
}

@Composable
fun VirtProbeScreen() {
    val context = LocalContext.current
    val activity = context as ComponentActivity
    val scope = rememberCoroutineScope()
    var report by remember { mutableStateOf<ProbeReport?>(null) }
    var scanning by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var page by remember { mutableStateOf(Page.Home) }
    var selectedId by remember { mutableStateOf<String?>(null) }
    var query by remember { mutableStateOf("") }
    var statusFilter by remember { mutableStateOf(StatusFilter.All) }
    var groupFilter by remember { mutableStateOf<UiGroup?>(null) }
    var filterOpen by remember { mutableStateOf(false) }
    var collapsed by remember { mutableStateOf(setOf<UiGroup>()) }
    var showJson by remember { mutableStateOf(false) }
    var trace by remember { mutableStateOf<InputNarrative?>(null) }
    var savedIndex by remember { mutableIntStateOf(0) }
    var savedOffset by remember { mutableIntStateOf(0) }
    var restoreScroll by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()

    fun rescan() {
        if (scanning) return
        scope.launch {
            scanning = true
            error = null
            try {
                val value = withContext(Dispatchers.IO) { VirtProbe.scan(activity) }
                report = value
                runCatching {
                    val dir = activity.getExternalFilesDir(null) ?: return@runCatching
                    java.io.File(dir, "last-report.json").writeText(ReportJson.stringify(value))
                }
            } catch (t: Throwable) {
                error = t.message ?: t.javaClass.simpleName
            } finally {
                scanning = false
            }
        }
    }

    LaunchedEffect(Unit) { rescan() }
    LaunchedEffect(restoreScroll, selectedId, page) {
        if (restoreScroll && selectedId == null && page == Page.Home) {
            listState.scrollToItem(savedIndex, savedOffset)
            restoreScroll = false
        }
    }

    val view = LocalView.current
    DisposableEffect(view) {
        val window = activity.window
        val previous = window.callback
        window.callback = VirtProbeWindowCallback(previous) { trace = it }
        onDispose { window.callback = previous }
    }

    val findings = report?.findings.orEmpty()
    val rows = findings.map { it to rowStatus(it) }
    val visible = rows.filter { (finding, status) ->
        val group = groupOf(finding)
        if (groupFilter != null && group != groupFilter) return@filter false
        if (!scanning && statusFilter != StatusFilter.All && status != statusFilter.toRow()) return@filter false
        val needle = query.trim()
        if (needle.isNotEmpty()) {
            val hay = "${finding.titleZh} ${finding.summaryZh} ${group.label} ${finding.signalId}"
            if (!hay.contains(needle, ignoreCase = true)) return@filter false
        }
        true
    }
    val counted = rows.filter { (finding, _) ->
        val group = groupOf(finding)
        if (groupFilter != null && group != groupFilter) return@filter false
        val needle = query.trim()
        if (needle.isNotEmpty()) {
            val hay = "${finding.titleZh} ${finding.summaryZh} ${group.label}"
            if (!hay.contains(needle, ignoreCase = true)) return@filter false
        }
        true
    }

    BackHandler(enabled = filterOpen || selectedId != null || page == Page.Input) {
        when {
            filterOpen -> filterOpen = false
            selectedId != null -> {
                selectedId = null
                restoreScroll = true
            }
            page == Page.Input -> {
                page = Page.Home
                restoreScroll = true
            }
        }
    }

    MaterialTheme(colorScheme = lightColorScheme(primary = Ink, background = Paper, surface = Card, onBackground = Ink, onSurface = Ink)) {
        Surface(
            modifier = Modifier
                .fillMaxSize()
                .windowInsetsPadding(WindowInsets.safeDrawing.union(WindowInsets.ime)),
            color = Paper,
        ) {
            Box(Modifier.fillMaxSize()) {
            Column(Modifier.fillMaxSize()) {
                TopBar(
                    title = when {
                        selectedId != null -> findings.firstOrNull { it.signalId == selectedId }?.titleZh ?: "详情"
                        page == Page.Input -> "输入体验"
                        else -> "异常信号检测器"
                    },
                    showBack = selectedId != null,
                    onBack = {
                        selectedId = null
                        restoreScroll = true
                    },
                )
                Box(Modifier.weight(1f).fillMaxWidth()) {
                    when {
                        page == Page.Home && selectedId == null -> HomeList(
                            report = report,
                            scanning = scanning,
                            error = error,
                            visible = visible,
                            totals = rows.map { it.second },
                            query = query,
                            onQuery = { query = it },
                            filterLabel = filterLabel(statusFilter, groupFilter),
                            onFilter = { filterOpen = true },
                            onRescan = ::rescan,
                            onExport = { showJson = true },
                            collapsed = collapsed,
                            onToggle = { group ->
                                collapsed = if (group in collapsed) collapsed - group else collapsed + group
                            },
                            listState = listState,
                            onOpen = { id ->
                                savedIndex = listState.firstVisibleItemIndex
                                savedOffset = listState.firstVisibleItemScrollOffset
                                selectedId = id
                                filterOpen = false
                                restoreScroll = true
                            },
                            scanningStatus = scanning,
                        )
                        page == Page.Home && selectedId != null -> {
                            val index = visible.indexOfFirst { it.first.signalId == selectedId }
                            val finding = findings.firstOrNull { it.signalId == selectedId }
                            if (finding == null) {
                                Text("这项不在当前报告里。", modifier = Modifier.padding(16.dp), color = Ink)
                            } else {
                                DetailPage(
                                    finding = finding,
                                    scanning = scanning,
                                    indexLabel = if (index >= 0) "${index + 1} / ${visible.size}" else "",
                                    hasPrev = index > 0,
                                    hasNext = index >= 0 && index < visible.lastIndex,
                                    onPrev = { selectedId = visible[index - 1].first.signalId },
                                    onNext = { selectedId = visible[index + 1].first.signalId },
                                )
                            }
                        }
                        else -> InputPage(trace)
                    }
                }
                if (selectedId == null) {
                    BottomNav(page) { next ->
                        if (next != page) {
                            if (page == Page.Home) {
                                savedIndex = listState.firstVisibleItemIndex
                                savedOffset = listState.firstVisibleItemScrollOffset
                                restoreScroll = true
                            }
                            page = next
                            filterOpen = false
                            selectedId = null
                        }
                    }
                }
            }
            if (filterOpen && page == Page.Home && selectedId == null) {
                FilterSheet(
                    statusFilter = statusFilter,
                    groupFilter = groupFilter,
                    counts = counted.groupingBy { it.second }.eachCount(),
                    total = counted.size,
                    onStatus = { statusFilter = it },
                    onGroup = { group ->
                        groupFilter = group
                        if (group != null) collapsed = collapsed - group
                    },
                    onReset = {
                        statusFilter = StatusFilter.All
                        groupFilter = null
                        query = ""
                    },
                    onClose = { filterOpen = false },
                )
            }
            }
        }
    }

    if (showJson && report != null) {
        JsonDialog(report!!.toPrettyJson()) { showJson = false }
    }
}

private fun StatusFilter.toRow(): RowStatus = when (this) {
    StatusFilter.Clue -> RowStatus.Clue
    StatusFilter.Clear -> RowStatus.Clear
    StatusFilter.Restricted -> RowStatus.Restricted
    StatusFilter.All -> RowStatus.Clear
}

private fun filterLabel(status: StatusFilter, group: UiGroup?): String {
    if (status == StatusFilter.All && group == null) return "筛选"
    val statusText = when (status) {
        StatusFilter.All -> "全部状态"
        StatusFilter.Clue -> "发现线索"
        StatusFilter.Clear -> "未发现线索"
        StatusFilter.Restricted -> "无法检查"
    }
    return if (group == null) "筛选·$statusText" else "筛选·$statusText·${group.label}"
}

@Composable
private fun TopBar(title: String, showBack: Boolean, onBack: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp).padding(end = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (showBack) {
            Text(
                "返回",
                color = Ink,
                fontWeight = FontWeight.Medium,
                modifier = Modifier.clickable(onClick = onBack).padding(horizontal = 16.dp, vertical = 14.dp),
            )
        }
        Text(
            title,
            color = Ink,
            fontWeight = FontWeight.SemiBold,
            fontSize = 18.sp,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(start = if (showBack) 0.dp else 16.dp, top = 12.dp, bottom = 12.dp),
        )
    }
}

@Composable
private fun HomeList(
    report: ProbeReport?,
    scanning: Boolean,
    error: String?,
    visible: List<Pair<SignalFinding, RowStatus>>,
    totals: List<RowStatus>,
    query: String,
    onQuery: (String) -> Unit,
    filterLabel: String,
    onFilter: () -> Unit,
    onRescan: () -> Unit,
    onExport: () -> Unit,
    collapsed: Set<UiGroup>,
    onToggle: (UiGroup) -> Unit,
    listState: LazyListState,
    onOpen: (String) -> Unit,
    scanningStatus: Boolean,
) {
    Column(Modifier.fillMaxSize()) {
        Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                when {
                    error != null -> "这次扫描没有完成"
                    scanning || report == null -> "正在扫描本机环境。"
                    else -> report.conclusionTitleZh
                },
                color = Ink,
                fontWeight = FontWeight.SemiBold,
                fontSize = 18.sp,
            )
            Text(
                text = error ?: if (scanning || report == null) {
                    "正在读取属性、文件和输入设备。"
                } else {
                    "已检查 ${totals.size} · 线索 ${totals.count { it == RowStatus.Clue }} · 未发现 ${totals.count { it == RowStatus.Clear }} · 无法检查 ${totals.count { it == RowStatus.Restricted }}"
                },
                color = Muted,
                fontSize = 13.sp,
            )
            if (!scanning && report != null && error == null) {
                Text(oneSentence(report.conclusionSummaryZh, 88), color = Ink, fontSize = 14.sp, lineHeight = 20.sp)
            }
            if (scanning) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth(), color = Ink, trackColor = Line)
            }
            Button(
                onClick = onRescan,
                enabled = !scanning,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Ink, contentColor = Color.White, disabledContainerColor = Line, disabledContentColor = Muted),
            ) { Text(if (scanning) "扫描中" else "重新扫描") }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = query,
                    onValueChange = onQuery,
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                    placeholder = { Text("搜索检查名称") },
                )
                TextButton(onClick = onFilter) { Text(filterLabel, color = Ink) }
            }
            TextButton(onClick = onExport, enabled = report != null) { Text("导出 JSON") }
        }
        if (!scanning && visible.isEmpty()) {
            Text("没有相符项。可清空搜索或改回全部。", color = Muted, modifier = Modifier.padding(16.dp))
        } else {
            LazyColumn(state = listState, modifier = Modifier.fillMaxSize()) {
                UiGroup.entries.forEach { group ->
                    val groupRows = visible.filter { groupOf(it.first) == group }
                    if (groupRows.isEmpty()) return@forEach
                    item(key = "group-$group") {
                        val clues = groupRows.count { it.second == RowStatus.Clue }
                        val open = group !in collapsed
                        Column(
                            Modifier
                                .fillMaxWidth()
                                .clickable { onToggle(group) }
                                .padding(horizontal = 16.dp, vertical = 12.dp),
                        ) {
                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                Text(group.label, color = Ink, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
                                Text(
                                    "${if (open) "收起" else "展开"} · ${groupRows.size}" + if (clues > 0) " · 线索 $clues" else "",
                                    color = Muted,
                                    fontSize = 12.sp,
                                )
                            }
                        }
                    }
                    if (group !in collapsed) {
                        items(groupRows, key = { it.first.signalId }) { (finding, status) ->
                            val shown = if (scanningStatus) RowStatus.Pending else status
                            Column(
                                Modifier
                                    .fillMaxWidth()
                                    .clickable { onOpen(finding.signalId) }
                                    .padding(horizontal = 16.dp, vertical = 12.dp),
                            ) {
                                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text(finding.titleZh, color = Ink, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f), maxLines = 2)
                                    Text(shown.label, color = shown.color(), fontSize = 13.sp, fontWeight = FontWeight.Medium)
                                }
                                Text(oneSentence(finding.summaryZh, 48), color = Muted, fontSize = 13.sp, maxLines = 2)
                            }
                        }
                    }
                }
            }
        }
    }
}

private fun RowStatus.color(): Color = when (this) {
    RowStatus.Clue -> Clue
    RowStatus.Restricted -> Restricted
    RowStatus.Pending -> Muted
    RowStatus.Clear -> Muted
}

@Composable
private fun DetailPage(
    finding: SignalFinding,
    scanning: Boolean,
    indexLabel: String,
    hasPrev: Boolean,
    hasNext: Boolean,
    onPrev: () -> Unit,
    onNext: () -> Unit,
) {
    var tech by remember(finding.signalId) { mutableStateOf(false) }
    val status = if (scanning) RowStatus.Pending else rowStatus(finding)
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("${groupOf(finding).label} · ${finding.signalId}", color = Muted, fontSize = 12.sp)
        Text(status.label, color = status.color(), fontWeight = FontWeight.Medium)
        if (scanning) {
            Text("正在扫描，当前项待检测。", color = Muted)
        } else {
            Field("结论", oneSentence(finding.summaryZh))
            Field("实际值", briefActual(finding.observedDataZh))
            Field("参考值", oneSentence(finding.expectedBaselineZh))
            Field("建议", oneSentence(finding.recommendationZh))
        }
        TextButton(onClick = { tech = !tech }, modifier = Modifier.fillMaxWidth()) {
            Text(if (tech) "收起技术详情" else "技术详情", color = Ink)
        }
        if (tech) {
            Text("来源", color = Muted, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
            Text(finding.sourceAttribution, color = Ink, fontSize = 13.sp)
            Text("局限", color = Muted, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
            Text(
                if (status == RowStatus.Restricted) "读不到或被拒绝是未知，不是未发现线索。"
                else "未命中不能单独证明环境正常。线索也不等于恶意。",
                color = Ink,
                fontSize = 13.sp,
            )
            Text("原始证据", color = Muted, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
            Text(finding.observedDataZh, color = Ink, fontSize = 13.sp, lineHeight = 18.sp)
            Text(finding.expectedBaselineZh, color = Muted, fontSize = 12.sp, lineHeight = 18.sp)
            finding.rawEvidence.forEach { (key, value) ->
                Text("$key = ${value.ifBlank { "（空）" }}", fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = Ink)
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onPrev, enabled = hasPrev) { Text("上一项") }
            TextButton(onClick = onNext, enabled = hasNext) { Text("下一项") }
            if (indexLabel.isNotBlank()) Text(indexLabel, color = Muted, fontSize = 12.sp)
        }
    }
}

@Composable
private fun Field(label: String, body: String) {
    Column {
        Text(label, color = Muted, fontSize = 12.sp)
        Text(body, color = Ink, fontSize = 16.sp, lineHeight = 22.sp)
    }
}

@Composable
private fun InputPage(trace: InputNarrative?) {
    val context = LocalContext.current
    val activity = context as ComponentActivity
    val view = LocalView.current
    var draft by remember { mutableStateOf("") }
    var tech by remember { mutableStateOf(false) }
    var slots by remember { mutableStateOf(mapOf<String, String>()) }
    var pads by remember { mutableStateOf(mapOf<String, Pad>()) }
    var tapAt by remember { mutableStateOf<Pair<Float, Float>?>(null) }
    var tick by remember { mutableIntStateOf(0) }
    DisposableEffect(activity) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) tick += 1
        }
        activity.lifecycle.addObserver(observer)
        onDispose { activity.lifecycle.removeObserver(observer) }
    }
    val serviceOn = remember(tick) { ProbeGestureService.isEnabled(context) }
    LaunchedEffect(trace?.sequence) {
        val current = trace ?: return@LaunchedEffect
        if (!current.settled || current.gestureZh.isBlank()) return@LaunchedEffect
        val pad = pads.entries.firstOrNull { it.value.contains(current.x, current.y) }?.key
        if (pad != null) slots = slots + (pad to current.headlineZh)
        val dir = activity.getExternalFilesDir(null) ?: return@LaunchedEffect
        val line = buildString {
            append("{\"seq\":").append(current.sequence)
            append(",\"gesture\":\"").append(current.gestureZh).append('"')
            append(",\"headline\":\"").append(current.headlineZh).append('"')
            append(",\"verdict\":\"").append(jsonEscape(current.verdictZh)).append('"')
            append(",\"observed\":\"").append(jsonEscape(current.observedDataZh)).append('"')
            append(",\"capability\":\"").append(jsonEscape(current.capabilityZh)).append('"')
            append(",\"detail\":\"").append(jsonEscape(current.detailZh)).append('"')
            append(",\"notes\":\"").append(jsonEscape(current.notesZh.joinToString("；"))).append("\"}\n")
        }
        java.io.File(dir, "input-events.jsonl").appendText(line)
    }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text("这是观测，不是真人认证。", color = Muted, fontSize = 13.sp)
        val headline = trace?.headlineZh?.ifBlank { null } ?: "还没有输入"
        val headlineColor = when (trace?.headlineZh) {
            "发现输入异常线索" -> Clue
            "证据不足" -> Restricted
            else -> Muted
        }
        Text(headline, color = headlineColor, fontWeight = FontWeight.Medium, fontSize = 18.sp)
        if (trace != null) {
            Text(oneSentence(trace.verdictZh, 80), color = Ink, fontSize = 16.sp, lineHeight = 22.sp)
            Text(oneSentence(trace.observedDataZh, 80), color = Muted, fontSize = 13.sp)
            if (trace.capabilityZh.isNotBlank()) Text(trace.capabilityZh, color = Muted, fontSize = 13.sp)
            trace.notesZh.firstOrNull { "遮挡" in it }?.let { Text(it, color = Ink, fontSize = 13.sp) }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
            GuidePad("点一下", slots["点击"], Modifier.weight(1f).onGloballyPositioned { coords ->
                pads = pads + ("点击" to coords.toPad(view))
                val pad = pads.getValue("点击")
                tapAt = (pad.left + pad.right) / 2f to (pad.top + pad.bottom) / 2f
            })
            GuidePad("按住", slots["长按"], Modifier.weight(1f).onGloballyPositioned { coords ->
                pads = pads + ("长按" to coords.toPad(view))
            })
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
            GuidePad("滑动", slots["滑动"], Modifier.weight(1f).onGloballyPositioned { coords ->
                pads = pads + ("滑动" to coords.toPad(view))
            })
            GuidePad("双指", slots["多指"], Modifier.weight(1f).onGloballyPositioned { coords ->
                pads = pads + ("多指" to coords.toPad(view))
            })
        }
        OutlinedTextField(
            value = draft,
            onValueChange = { draft = it },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            placeholder = { Text("测试输入，不要填密码") },
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = {
                if (!ProbeGestureService.isEnabled(context)) {
                    context.startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
                } else {
                    val at = tapAt ?: return@TextButton
                    ProbeGestureService.tap(at.first, at.second)
                }
            }) { Text(if (serviceOn) "无障碍测试点击" else "开启测试服务") }
            TextButton(onClick = {
                if (!ProbeGestureService.isEnabled(context)) {
                    context.startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
                } else {
                    val at = tapAt ?: return@TextButton
                    ProbeGestureService.twoFinger(at.first, at.second)
                }
            }, enabled = serviceOn) { Text("无障碍双指") }
        }
        TextButton(onClick = { tech = !tech }) { Text(if (tech) "收起技术详情" else "技术详情", color = Ink) }
        if (tech && trace != null) {
            Text(trace.detailZh, color = Ink, fontSize = 13.sp, lineHeight = 18.sp)
            trace.notesZh.forEach { Text(it, color = Muted, fontSize = 12.sp) }
            trace.findings.forEach { Text("${it.signalId} ${it.summaryZh}", color = Muted, fontSize = 12.sp) }
            Text(trace.expectedBaselineZh, color = Muted, fontSize = 12.sp, lineHeight = 18.sp)
        }
    }
}

@Composable
private fun GuidePad(title: String, result: String?, modifier: Modifier) {
    Column(
        modifier
            .height(84.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(Card)
            .border(1.dp, Line, RoundedCornerShape(12.dp))
            .padding(10.dp),
        verticalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(title, color = Ink, fontWeight = FontWeight.Medium)
        Text(result ?: "未做", color = Muted, fontSize = 12.sp)
    }
}

private data class Pad(val left: Float, val top: Float, val right: Float, val bottom: Float) {
    fun contains(x: Float, y: Float): Boolean = x in left..right && y in top..bottom
}

private fun androidx.compose.ui.layout.LayoutCoordinates.toPad(view: android.view.View): Pad {
    val origin = IntArray(2)
    view.getLocationOnScreen(origin)
    val pos = positionInWindow()
    return Pad(
        left = origin[0] + pos.x,
        top = origin[1] + pos.y,
        right = origin[0] + pos.x + size.width,
        bottom = origin[1] + pos.y + size.height,
    )
}

private fun jsonEscape(value: String): String {
    return value.replace("\\", "\\\\").replace("\"", "'").replace("\n", " ")
}

@Composable
private fun BottomNav(page: Page, onSelect: (Page) -> Unit) {
    Row(Modifier.fillMaxWidth().background(Card)) {
        NavKey("检测", page == Page.Home) { onSelect(Page.Home) }
        NavKey("输入体验", page == Page.Input) { onSelect(Page.Input) }
    }
}

@Composable
private fun androidx.compose.foundation.layout.RowScope.NavKey(label: String, selected: Boolean, onClick: () -> Unit) {
    Text(
        label,
        color = if (selected) Ink else Muted,
        fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
        modifier = Modifier.weight(1f).clickable(onClick = onClick).padding(vertical = 16.dp),
        textAlign = androidx.compose.ui.text.style.TextAlign.Center,
    )
}

@Composable
private fun FilterSheet(
    statusFilter: StatusFilter,
    groupFilter: UiGroup?,
    counts: Map<RowStatus, Int>,
    total: Int,
    onStatus: (StatusFilter) -> Unit,
    onGroup: (UiGroup?) -> Unit,
    onReset: () -> Unit,
    onClose: () -> Unit,
) {
    Box(Modifier.fillMaxSize()) {
        Box(Modifier.fillMaxSize().background(Color(0x99000000)).clickable(onClick = onClose))
        Column(
            Modifier
                .align(Alignment.BottomCenter)
                .fillMaxWidth()
                .heightIn(max = 560.dp)
                .background(Card)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text("筛选", color = Ink, fontWeight = FontWeight.SemiBold, fontSize = 18.sp)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                Button(onClick = onReset, modifier = Modifier.weight(1f), colors = ButtonDefaults.buttonColors(containerColor = Paper, contentColor = Ink)) {
                    Text("重置筛选")
                }
                Button(onClick = onClose, modifier = Modifier.weight(1f), colors = ButtonDefaults.buttonColors(containerColor = Ink, contentColor = Color.White)) {
                    Text("完成")
                }
            }
            Text("状态", color = Muted, fontSize = 12.sp)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                Chip("全部 $total", statusFilter == StatusFilter.All) { onStatus(StatusFilter.All) }
                Chip("发现线索 ${counts[RowStatus.Clue] ?: 0}", statusFilter == StatusFilter.Clue) { onStatus(StatusFilter.Clue) }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Chip("未发现线索 ${counts[RowStatus.Clear] ?: 0}", statusFilter == StatusFilter.Clear) { onStatus(StatusFilter.Clear) }
                Chip("无法检查 ${counts[RowStatus.Restricted] ?: 0}", statusFilter == StatusFilter.Restricted) { onStatus(StatusFilter.Restricted) }
            }
            Text("分组", color = Muted, fontSize = 12.sp)
            Chip("全部分组", groupFilter == null) { onGroup(null) }
            UiGroup.entries.forEach { group ->
                Chip(group.label, groupFilter == group) { onGroup(group) }
            }
        }
    }
}

@Composable
private fun Chip(label: String, selected: Boolean, onClick: () -> Unit) {
    Text(
        label,
        color = if (selected) Color.White else Ink,
        fontSize = 13.sp,
        modifier = Modifier
            .clip(RoundedCornerShape(999.dp))
            .background(if (selected) Ink else Paper)
            .border(1.dp, if (selected) Ink else Line, RoundedCornerShape(999.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 8.dp),
    )
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
