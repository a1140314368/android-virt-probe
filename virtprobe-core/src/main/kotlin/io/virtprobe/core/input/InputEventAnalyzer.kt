// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.core.input

import io.virtprobe.core.catalog.Attribution
import io.virtprobe.core.catalog.KnownSignals
import io.virtprobe.core.model.InputEventBits
import io.virtprobe.core.model.InputNarrative
import io.virtprobe.core.model.InputSourceBits
import io.virtprobe.core.model.KeySample
import io.virtprobe.core.model.MotionSample
import io.virtprobe.core.model.Severity
import io.virtprobe.core.model.SignalCategory
import io.virtprobe.core.model.SignalFinding
import io.virtprobe.core.model.finding
import kotlin.math.abs
import kotlin.math.sqrt

/**
 * 实时触控和按键溯源。调用方传入当前事件，以及同一手势的历史点和近期按下时间。
 * 滑动窗口里的运动学只在样本够了以后才命中，避免把正常的短点击误报成直线。
 */
object InputEventAnalyzer {
    private val category = SignalCategory.INPUT
    private const val FINGER_BASELINE =
        "真实手指触控应来自物理触控芯片 isVirtual=false 且具备动态压力与触控面积变化。"

    fun analyzeMotion(history: List<MotionSample>, recentDownTimes: List<Long> = emptyList()): List<SignalFinding> {
        val current = history.lastOrNull() ?: return emptyList()
        val gesture = history.filter { it.downTime == current.downTime }
        return listOfNotNull(
            motionDevice(current),
            obscured(current),
            accessibility(current, "in.event.accessibility"),
            motionSource(current),
            kinematics(current, gesture, recentDownTimes),
        )
    }

    fun analyzeKey(sample: KeySample): List<SignalFinding> {
        return listOfNotNull(
            keyDevice(sample),
            keyAccessibility(sample),
        )
    }

    fun narrateMotion(sample: MotionSample, findings: List<SignalFinding>): InputNarrative {
        return narrate(
            findings = findings,
            measured = motionMeasured(sample),
            cleanVerdict = "本次输入未看到明显注入特征。这是启发式判断，不能证明来自物理手指。",
            mildVerdict = "本次输入带有低敏特征，还不能单独定性为注入",
            suspiciousVerdict = "本次输入疑似虚拟注入或自动化",
        )
    }

    fun narrateKey(sample: KeySample, findings: List<SignalFinding>): InputNarrative {
        val softKeyboard = sample.deviceId <= 0 && findings.none { it.detected && it.severity.atLeast(Severity.MEDIUM) }
        return narrate(
            findings = findings,
            measured = keyMeasured(sample),
            cleanVerdict = "本次按键未看到明显注入特征。这是启发式判断，不能证明来自物理键盘。",
            mildVerdict = if (softKeyboard) "本次按键来自系统软键盘（虚拟设备），未见注入特征" else "本次按键带有低敏特征",
            suspiciousVerdict = "本次按键疑似虚拟注入或自动化",
        )
    }

    private fun narrate(
        findings: List<SignalFinding>,
        measured: String,
        cleanVerdict: String,
        mildVerdict: String,
        suspiciousVerdict: String,
    ): InputNarrative {
        val serious = findings.filter { it.detected && it.severity.atLeast(Severity.MEDIUM) }
        val mild = findings.filter { it.detected && it.severity == Severity.LOW }
        val primary = (serious.ifEmpty { mild }).maxByOrNull { it.severity.ordinal }
        val suspicious = serious.isNotEmpty()
        val verdict = when {
            suspicious -> suspiciousVerdict
            mild.isNotEmpty() -> mildVerdict
            else -> cleanVerdict
        }
        return InputNarrative(
            suspicious = suspicious,
            verdictZh = verdict,
            observedDataZh = primary?.observedDataZh ?: measured,
            expectedBaselineZh = primary?.expectedBaselineZh ?: FINGER_BASELINE,
            recommendationZh = primary?.recommendationZh
                ?: "本次输入未发现虚拟注入特征，可按正常触控继续。若业务极敏感，仍可保留原始事件做抽查。",
            findings = findings,
        )
    }

    private fun motionDevice(sample: MotionSample): SignalFinding? {
        val name = sample.deviceName.orEmpty()
        val named = KnownSignals.INPUT_NAME_MARKERS.any { it in name.lowercase() }
        val virtual = sample.isDeviceVirtual == true || sample.deviceId <= 0 || named
        if (!virtual) return null
        val soft = sample.deviceId == InputEventBits.DEVICE_ID_VIRTUAL_KEYBOARD && !named &&
            sample.source == InputSourceBits.SOURCE_KEYBOARD
        return finding(
            signalId = "in.event.device",
            category = category,
            severity = if (soft) Severity.LOW else Severity.HIGH,
            confidence = if (named || sample.deviceId <= 0) 0.92 else 0.86,
            detected = true,
            titleZh = "触控事件的设备来源",
            summaryZh = if (soft) "事件来自虚拟键盘设备号。" else "触控事件来自虚拟设备、非正设备号，或设备名像注入器。",
            observedDataZh = motionMeasured(sample),
            expectedBaselineZh = FINGER_BASELINE,
            recommendationZh = if (soft) {
                "系统软键盘使用虚拟设备号是正常现象。若这是一次触摸而不是按键，应拒绝并要求真实触控。"
            } else {
                "本次输入疑似脚本或远程注入，建议拒绝本次操作并要求真实触控复核。"
            },
            rawEvidence = motionEvidence(sample),
            sourceAttribution = Attribution.INPUT,
        )
    }

    private fun obscured(sample: MotionSample): SignalFinding? {
        val full = sample.flags and InputEventBits.FLAG_WINDOW_IS_OBSCURED != 0
        val partial = sample.flags and InputEventBits.FLAG_WINDOW_IS_PARTIALLY_OBSCURED != 0
        if (!full && !partial) return null
        return finding(
            signalId = "in.event.obscured",
            category = category,
            severity = if (full) Severity.HIGH else Severity.MEDIUM,
            confidence = 0.9,
            detected = true,
            titleZh = "窗口被遮挡的触控",
            summaryZh = if (full) "触摸穿过了上层窗口，存在点击劫持风险。" else "窗口部分区域被遮挡。",
            observedDataZh = "${motionMeasured(sample)} 遮挡标志：完全遮挡=$full，部分遮挡=$partial。",
            expectedBaselineZh = "用户直接点在本窗口上时，不应带 FLAG_WINDOW_IS_OBSCURED。部分遮挡表示触摸点以外的区域有悬浮窗，也需要提示用户。",
            recommendationZh = "存在遮挡点击风险，建议丢弃这次触摸，提示关闭悬浮窗，并对敏感按钮做二次确认。",
            rawEvidence = motionEvidence(sample),
            sourceAttribution = Attribution.INPUT,
        )
    }

    private fun accessibility(sample: MotionSample, signalId: String): SignalFinding? {
        if (sample.flags and InputEventBits.FLAG_IS_ACCESSIBILITY_EVENT == 0) return null
        return accessibilityFinding(signalId, motionMeasured(sample), motionEvidence(sample))
    }

    private fun keyAccessibility(sample: KeySample): SignalFinding? {
        if (sample.flags and InputEventBits.FLAG_IS_ACCESSIBILITY_EVENT == 0) return null
        return accessibilityFinding("in.event.accessibility", keyMeasured(sample), keyEvidence(sample))
    }

    private fun accessibilityFinding(signalId: String, observed: String, evidence: Map<String, String>): SignalFinding {
        return finding(
            signalId = signalId,
            category = category,
            severity = Severity.HIGH,
            confidence = 0.93,
            detected = true,
            titleZh = "无障碍服务生成的输入",
            summaryZh = "事件带有无障碍生成标志。",
            observedDataZh = "$observed 标志位包含 FLAG_IS_ACCESSIBILITY_EVENT（0x800），表示事件由无障碍服务产生或改写。",
            expectedBaselineZh = "真实手指或物理键盘不会设置这个标志。它和「系统里安装了无障碍服务」不是一回事，而是这一次事件本身来自无障碍注入。",
            recommendationZh = "本次输入由无障碍服务生成，建议拒绝敏感操作，除非产品明确允许辅助功能代操作。",
            rawEvidence = evidence,
            sourceAttribution = Attribution.INPUT,
        )
    }

    private fun motionSource(sample: MotionSample): SignalFinding? {
        val unknownTool = sample.toolType == InputEventBits.TOOL_TYPE_UNKNOWN
        val emptySource = sample.source == 0 || sample.source == InputSourceBits.SOURCE_ANY
        val mouseOnTouch = sample.toolType == InputEventBits.TOOL_TYPE_MOUSE &&
            sample.source and InputSourceBits.SOURCE_TOUCHSCREEN == InputSourceBits.SOURCE_TOUCHSCREEN
        if (!unknownTool && !emptySource && !mouseOnTouch) return null
        return finding(
            signalId = "in.event.source",
            category = category,
            severity = if (emptySource) Severity.HIGH else Severity.MEDIUM,
            confidence = 0.84,
            detected = true,
            titleZh = "触控来源与工具类型异常",
            summaryZh = "事件的 source 或 toolType 不像手指按在触摸屏上。",
            observedDataZh = "${motionMeasured(sample)} source=${sourceName(sample.source)}，toolType=${toolName(sample.toolType)}。",
            expectedBaselineZh = "手指触摸的 source 应为 SOURCE_TOUCHSCREEN，toolType 应为 TOOL_TYPE_FINGER。source 为 0 或 SOURCE_ANY、toolType 为 UNKNOWN，常见于 adb 注入的点击。",
            recommendationZh = "事件来源不像物理手指，建议拒绝本次点击并要求重新用手指操作。",
            rawEvidence = motionEvidence(sample),
            sourceAttribution = Attribution.INPUT,
        )
    }

    private fun kinematics(
        current: MotionSample,
        gesture: List<MotionSample>,
        recentDownTimes: List<Long>,
    ): SignalFinding? {
        val reasons = mutableListOf<String>()
        val up = (current.action and InputEventBits.ACTION_MASK) == InputEventBits.ACTION_UP
        if (up && current.eventTime == current.downTime) {
            reasons += "抬起时间等于按下时间，点击时长为 0"
        }
        val moves = gesture.filter { (it.action and InputEventBits.ACTION_MASK) == InputEventBits.ACTION_MOVE }
        if (moves.size >= 4) {
            val pressures = moves.map { it.pressure }.distinct()
            val majors = moves.map { it.touchMajor }.distinct()
            val sizes = moves.map { it.size }.distinct()
            if (pressures.size == 1 && majors.size == 1 && sizes.size == 1) {
                val pressure = pressures.first()
                val major = majors.first()
                if (pressure == 0f || major == 0f || pressure == 1f) {
                    reasons += "连续 ${moves.size} 个移动点的 pressure=$pressure、touchMajor=$major、size=${sizes.first()} 完全不变"
                }
            }
        }
        if (moves.size >= 6 && isMechanicalLine(moves)) {
            reasons += "连续 ${moves.size} 个移动点为零抖动直线，步长几乎完全相等"
        }
        val rhythm = mechanicalRhythm(recentDownTimes)
        if (rhythm != null) reasons += rhythm
        if (reasons.isEmpty()) return null
        val zeroClick = reasons.any { "时长为 0" in it }
        return finding(
            signalId = "in.event.kinematics",
            category = category,
            severity = if (zeroClick) Severity.HIGH else Severity.MEDIUM,
            confidence = 0.8,
            detected = true,
            titleZh = "触控运动学异常",
            summaryZh = "滑动窗口里的压力、轨迹或点击节律不像手指。",
            observedDataZh = "${motionMeasured(current)} 异常：${reasons.joinToString("；")}。",
            expectedBaselineZh = FINGER_BASELINE + "真实滑动会有轻微抖动，点击的 eventTime 应晚于 downTime，连续点击间隔也不会精确到几乎为零方差。",
            recommendationZh = "触控轨迹呈机械特征，建议拒绝本次操作并要求真实触控复核。",
            rawEvidence = motionEvidence(current) + mapOf("reasons" to reasons.joinToString(" | ")),
            sourceAttribution = Attribution.INPUT,
        )
    }

    private fun keyDevice(sample: KeySample): SignalFinding? {
        val name = sample.deviceName.orEmpty()
        val named = KnownSignals.INPUT_NAME_MARKERS.any { it in name.lowercase() }
        val virtualId = sample.deviceId <= 0 || sample.isDeviceVirtual == true
        if (!virtualId && !named) return null
        val severe = named || sample.isDeviceVirtual == true && sample.deviceId != InputEventBits.DEVICE_ID_VIRTUAL_KEYBOARD
        return finding(
            signalId = "in.event.device",
            category = category,
            severity = if (severe) Severity.HIGH else Severity.LOW,
            confidence = if (severe) 0.88 else 0.45,
            detected = true,
            titleZh = "按键事件的设备来源",
            summaryZh = if (severe) "按键来自具名虚拟设备或注入器。" else "按键来自系统软键盘使用的虚拟设备号。",
            observedDataZh = keyMeasured(sample),
            expectedBaselineZh = "物理键盘的 deviceId 为正数且 isVirtual=false。软键盘使用 VIRTUAL_KEYBOARD=-1 是正常的；uinput、scrcpy、adb 等名字则不是软键盘。",
            recommendationZh = if (severe) {
                "按键来源像注入设备，建议拒绝本次输入。"
            } else {
                "系统软键盘本身是虚拟设备。若没有其它注入特征，不必仅凭 deviceId=-1 阻断。"
            },
            rawEvidence = keyEvidence(sample),
            sourceAttribution = Attribution.INPUT,
        )
    }

    private fun isMechanicalLine(moves: List<MotionSample>): Boolean {
        val start = moves.first()
        val end = moves.last()
        val dx = end.x - start.x
        val dy = end.y - start.y
        val length = sqrt(dx * dx + dy * dy)
        if (length < 40f) return false
        var maxDistance = 0.0
        val steps = mutableListOf<Double>()
        var previous = start
        for (point in moves.drop(1)) {
            val step = hypot(point.x - previous.x, point.y - previous.y)
            steps += step
            val distance = abs((point.x - start.x) * dy - (point.y - start.y) * dx) / length
            if (distance > maxDistance) maxDistance = distance.toDouble()
            previous = point
        }
        if (maxDistance > 0.5) return false
        val mean = steps.average()
        if (mean <= 0.0) return false
        val variance = steps.sumOf { (it - mean) * (it - mean) } / steps.size
        val cv = sqrt(variance) / mean
        return cv < 0.02
    }

    private fun mechanicalRhythm(downTimes: List<Long>): String? {
        if (downTimes.size < 5) return null
        val intervals = downTimes.zipWithNext { a, b -> (b - a).toDouble() }.filter { it in 15.0..500.0 }
        if (intervals.size < 4) return null
        val mean = intervals.average()
        if (mean <= 0.0) return null
        val variance = intervals.sumOf { (it - mean) * (it - mean) } / intervals.size
        val cv = sqrt(variance) / mean
        if (cv >= 0.03) return null
        return "最近 ${intervals.size} 次按下间隔均值 ${mean.toInt()} 毫秒，变异系数 ${format(cv)}，呈机械等间隔"
    }

    private fun motionMeasured(sample: MotionSample): String {
        return "deviceId=${sample.deviceId}，deviceName=${sample.deviceName ?: "（未知）"}，isVirtual=${sample.isDeviceVirtual}，" +
            "source=${sourceName(sample.source)}，toolType=${toolName(sample.toolType)}，flags=0x${sample.flags.toString(16)}，" +
            "pressure=${sample.pressure}，size=${sample.size}，touchMajor=${sample.touchMajor}，" +
            "坐标=(${sample.x}, ${sample.y})，eventTime=${sample.eventTime}，downTime=${sample.downTime}。"
    }

    private fun keyMeasured(sample: KeySample): String {
        return "keyCode=${sample.keyCode}，action=${sample.action}，deviceId=${sample.deviceId}，" +
            "deviceName=${sample.deviceName ?: "（未知）"}，isVirtual=${sample.isDeviceVirtual}，" +
            "source=${sourceName(sample.source)}，flags=0x${sample.flags.toString(16)}，" +
            "eventTime=${sample.eventTime}，downTime=${sample.downTime}。"
    }

    private fun motionEvidence(sample: MotionSample): Map<String, String> = mapOf(
        "deviceId" to sample.deviceId.toString(),
        "deviceName" to sample.deviceName.orEmpty(),
        "isVirtual" to sample.isDeviceVirtual.toString(),
        "source" to sample.source.toString(),
        "toolType" to sample.toolType.toString(),
        "flags" to sample.flags.toString(),
        "pressure" to sample.pressure.toString(),
        "size" to sample.size.toString(),
        "touchMajor" to sample.touchMajor.toString(),
        "x" to sample.x.toString(),
        "y" to sample.y.toString(),
        "eventTime" to sample.eventTime.toString(),
        "downTime" to sample.downTime.toString(),
    )

    private fun keyEvidence(sample: KeySample): Map<String, String> = mapOf(
        "keyCode" to sample.keyCode.toString(),
        "deviceId" to sample.deviceId.toString(),
        "deviceName" to sample.deviceName.orEmpty(),
        "isVirtual" to sample.isDeviceVirtual.toString(),
        "source" to sample.source.toString(),
        "flags" to sample.flags.toString(),
    )

    private fun sourceName(source: Int): String = when (source) {
        InputSourceBits.SOURCE_TOUCHSCREEN -> "TOUCHSCREEN"
        InputSourceBits.SOURCE_MOUSE -> "MOUSE"
        InputSourceBits.SOURCE_KEYBOARD -> "KEYBOARD"
        InputSourceBits.SOURCE_STYLUS -> "STYLUS"
        InputSourceBits.SOURCE_DPAD -> "DPAD"
        InputSourceBits.SOURCE_ANY -> "ANY"
        0 -> "0"
        else -> "0x${source.toString(16)}"
    }

    private fun toolName(tool: Int): String = when (tool) {
        InputEventBits.TOOL_TYPE_FINGER -> "FINGER"
        InputEventBits.TOOL_TYPE_MOUSE -> "MOUSE"
        InputEventBits.TOOL_TYPE_STYLUS -> "STYLUS"
        InputEventBits.TOOL_TYPE_UNKNOWN -> "UNKNOWN"
        else -> tool.toString()
    }

    private fun hypot(x: Float, y: Float): Double = sqrt((x * x + y * y).toDouble())

    private fun format(value: Double): String = ((value * 1000).toInt() / 1000.0).toString()
}
