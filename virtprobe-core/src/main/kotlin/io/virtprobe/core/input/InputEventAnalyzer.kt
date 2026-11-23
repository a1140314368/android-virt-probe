// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.core.input

import io.virtprobe.core.catalog.Attribution
import io.virtprobe.core.model.InputEventBits
import io.virtprobe.core.model.InputNarrative
import io.virtprobe.core.model.InputSourceBits
import io.virtprobe.core.model.KeySample
import io.virtprobe.core.model.MotionSample
import io.virtprobe.core.model.Severity
import io.virtprobe.core.model.SignalCategory
import io.virtprobe.core.model.SignalFinding
import io.virtprobe.core.model.finding
import kotlin.math.sqrt

/**
 * 实时触控和按键的来源观察。
 *
 * 只把平台自己标明的生成标志、设备身份和来源/工具类型不一致当作线索。
 * 压力、面积、时长和轨迹只写进备注，不设统一阈值，也不折成真实性分数。
 * isVirtual=false 不能证明真人；系统软键盘的虚拟设备也不能判作弊。
 * 遮挡标志单独说明，不算注入。
 */
object InputEventAnalyzer {
    const val HEAD_CLUE: String = "发现输入异常线索"
    const val HEAD_NONE: String = "本次未发现"
    const val HEAD_WEAK: String = "证据不足"

    private val category = SignalCategory.INPUT
    private const val BASELINE =
        "直接手指触控通常来自非虚拟触屏，工具类型是手指，且不带无障碍生成标志。isVirtual=false 不能证明真人。系统软键盘是虚拟设备，不能据此判作弊。"
    private const val ADVICE_CLUE = "核对技术详情里的标志和设备。这是观测，不是真人认证。"
    private const val ADVICE_NONE = "这次没有注入线索。这不能认证真人。"
    private const val ADVICE_WEAK = "不要把证据不足写成未发现，也不要写成已经确认注入。"

    /** 远程注入常见设备名。模拟器芯片名不在这里，避免把整台模拟器的普通触控都写成注入。 */
    private val injectorNames = listOf("uinput", "scrcpy", "vtouch", "inputinjector", "remote-desktop")

    /** 模拟器或虚拟机输入设备名。只能说明这里没有物理手指基线。 */
    private val emulatorNames = listOf(
        "goldfish", "ranchu", "virtio", "qwerty", "vbox", "genymotion", "bluestacks", "memu", "nox", "ldplayer",
    )

    /** 引导归类用的时长和位移，沿用长按大约半秒的习惯，不是真实性阈值。 */
    private const val GUIDE_LONG_MS = 500L
    private const val GUIDE_SWIPE_PX = 48.0

    fun analyzeMotion(history: List<MotionSample>): List<SignalFinding> {
        val current = history.lastOrNull() ?: return emptyList()
        return listOfNotNull(
            accessibility(current),
            injectorName(current),
            virtualTouchDevice(current),
            virtualKeyboardOnTouch(current),
            sourceAndTool(current),
            pointerTools(current),
            obscured(current),
        )
    }

    fun analyzeKey(sample: KeySample): List<SignalFinding> {
        return listOfNotNull(
            keyAccessibility(sample),
            keyInjector(sample),
            keySoftKeyboard(sample),
        )
    }

    fun narrateMotion(sample: MotionSample, findings: List<SignalFinding>): InputNarrative {
        return narrateMotion(listOf(sample), findings)
    }

    fun narrateMotion(history: List<MotionSample>, findings: List<SignalFinding>): InputNarrative {
        val current = history.lastOrNull()
            ?: return emptyNarrative()
        val gesture = history.filter { it.downTime == current.downTime }.ifEmpty { listOf(current) }
        val notes = mutableListOf<String>()
        obscuredNote(current)?.let { notes += it }
        emulatorNote(current.deviceName)?.let { notes += it }
        weakMotionNotes(current, gesture).forEach { notes += it }
        val clue = injection(findings)
        val missing = current.deviceMissing
        val headline = headline(clue, missing, notes)
        val sentence = motionSentence(headline, clue, notes, current)
        return InputNarrative(
            suspicious = clue != null,
            headlineZh = headline,
            verdictZh = sentence,
            observedDataZh = shortMotion(current),
            expectedBaselineZh = BASELINE,
            recommendationZh = advice(headline),
            findings = findings,
            notesZh = notes,
            detailZh = detailMotion(current, gesture),
            capabilityZh = capability(current),
            gestureZh = guideGesture(current, gesture),
            settled = isSettled(current.action),
            x = current.x,
            y = current.y,
        )
    }

    fun narrateKey(sample: KeySample, findings: List<SignalFinding>): InputNarrative {
        val notes = mutableListOf<String>()
        val soft = isSoftKeyboard(sample)
        if (soft) notes += "系统软键盘是虚拟设备。这不能判作弊。"
        emulatorNote(sample.deviceName)?.let { notes += it }
        val clue = injection(findings)
        val missing = sample.deviceName == null && sample.isDeviceVirtual == null && sample.deviceId != InputEventBits.DEVICE_ID_VIRTUAL_KEYBOARD
        val headline = when {
            clue != null -> HEAD_CLUE
            soft && notes.none { "模拟器" in it } -> HEAD_NONE
            missing || notes.any { "模拟器" in it } -> HEAD_WEAK
            else -> HEAD_NONE
        }
        val sentence = when {
            clue != null -> "${clue.summaryZh}这是观测，不是真人认证。"
            soft -> "系统软键盘是虚拟设备，不能判作弊，也不能证明来自真人。"
            headline == HEAD_WEAK -> "这次按键读不到足够的设备信息。"
            else -> "这次按键没有注入线索。这不能证明来自物理键盘。"
        }
        return InputNarrative(
            suspicious = clue != null,
            headlineZh = headline,
            verdictZh = sentence,
            observedDataZh = "按键设备=${sample.deviceId}，来源=${sourceName(sample.source)}，isVirtual=${sample.isDeviceVirtual}。不记录按键码。",
            expectedBaselineZh = "物理键盘的设备号为正数且 isVirtual=false。软键盘使用虚拟设备号是正常的。",
            recommendationZh = advice(headline),
            findings = findings,
            notesZh = notes,
            detailZh = "deviceId=${sample.deviceId}，deviceName=${sample.deviceName ?: "（未知）"}，isVirtual=${sample.isDeviceVirtual}，" +
                "source=${sourceName(sample.source)}，flags=0x${sample.flags.toString(16)}。不记录按键码。",
            capabilityZh = "",
            gestureZh = "",
            settled = sample.action == InputEventBits.ACTION_DOWN,
        )
    }

    private fun emptyNarrative(): InputNarrative = InputNarrative(
        suspicious = false,
        headlineZh = HEAD_WEAK,
        verdictZh = "还没有输入事件。",
        observedDataZh = "没有事件。",
        expectedBaselineZh = BASELINE,
        recommendationZh = ADVICE_WEAK,
        findings = emptyList(),
    )

    private fun injection(findings: List<SignalFinding>): SignalFinding? {
        return findings.filter {
            it.detected && it.severity.atLeast(Severity.MEDIUM) && it.signalId != "in.event.obscured"
        }.maxByOrNull { it.severity.ordinal }
    }

    private fun headline(clue: SignalFinding?, missing: Boolean, notes: List<String>): String {
        if (clue != null) return HEAD_CLUE
        val weak = missing || notes.any { "模拟器" in it || "时刻相同" in it || "压力值相同" in it || "面积值相同" in it || "长轴值相同" in it }
        return if (weak) HEAD_WEAK else HEAD_NONE
    }

    private fun motionSentence(
        headline: String,
        clue: SignalFinding?,
        notes: List<String>,
        sample: MotionSample,
    ): String = when (headline) {
        HEAD_CLUE -> "${clue?.summaryZh ?: "这次事件有来源线索。"}这是观测，不是真人认证。"
        HEAD_WEAK -> when {
            notes.any { "模拟器" in it } -> "设备名像模拟器输入，不能当物理手指基线。"
            notes.any { "时刻相同" in it || "相同" in it } -> "只有时长或压力这类弱观察，没有统一阈值。"
            sample.deviceMissing -> "读不到这次事件对应的输入设备。"
            else -> "现有字段不够区分这次输入。"
        }
        else -> "这次没有注入线索。isVirtual=${sample.isDeviceVirtual} 不能证明是真人。"
    }

    private fun advice(headline: String): String = when (headline) {
        HEAD_CLUE -> ADVICE_CLUE
        HEAD_WEAK -> ADVICE_WEAK
        else -> ADVICE_NONE
    }

    private fun accessibility(sample: MotionSample): SignalFinding? {
        if (sample.flags and InputEventBits.FLAG_IS_ACCESSIBILITY_EVENT == 0) return null
        return finding(
            signalId = "in.event.accessibility",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.9,
            detected = true,
            titleZh = "无障碍生成的输入",
            summaryZh = "这次事件带无障碍生成标志。",
            observedDataZh = "${shortMotion(sample)} 含 0x800。",
            expectedBaselineZh = "直接手指或物理键盘不会带这个标志。它只说明这次事件由无障碍服务生成或改写，不说明操作者不是人。",
            recommendationZh = ADVICE_CLUE,
            rawEvidence = evidence(sample),
            sourceAttribution = Attribution.INPUT,
        )
    }

    private fun keyAccessibility(sample: KeySample): SignalFinding? {
        if (sample.flags and InputEventBits.FLAG_IS_ACCESSIBILITY_EVENT == 0) return null
        return finding(
            signalId = "in.event.accessibility",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.9,
            detected = true,
            titleZh = "无障碍生成的按键",
            summaryZh = "这次按键带无障碍生成标志。",
            observedDataZh = "flags=0x${sample.flags.toString(16)}。不记录按键码。",
            expectedBaselineZh = "直接按键不会带这个标志。",
            recommendationZh = ADVICE_CLUE,
            rawEvidence = mapOf("flags" to sample.flags.toString()),
            sourceAttribution = Attribution.INPUT,
        )
    }

    private fun injectorName(sample: MotionSample): SignalFinding? {
        val name = matched(sample.deviceName, injectorNames) ?: return null
        return deviceFinding("设备名含注入器标记 $name。", sample)
    }

    private fun keyInjector(sample: KeySample): SignalFinding? {
        val name = matched(sample.deviceName, injectorNames) ?: return null
        return finding(
            signalId = "in.event.device",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.9,
            detected = true,
            titleZh = "按键设备名",
            summaryZh = "按键设备名含注入器标记 $name。",
            observedDataZh = "deviceId=${sample.deviceId}，deviceName=${sample.deviceName}。不记录按键码。",
            expectedBaselineZh = BASELINE,
            recommendationZh = ADVICE_CLUE,
            rawEvidence = mapOf("deviceName" to sample.deviceName.orEmpty()),
            sourceAttribution = Attribution.INPUT,
        )
    }

    private fun virtualTouchDevice(sample: MotionSample): SignalFinding? {
        if (sample.isDeviceVirtual != true) return null
        if (!hasSource(sample.source, InputSourceBits.SOURCE_TOUCHSCREEN)) return null
        if (sample.deviceId == InputEventBits.DEVICE_ID_VIRTUAL_KEYBOARD) return null
        return deviceFinding("触屏设备被系统标成虚拟设备。", sample)
    }

    private fun virtualKeyboardOnTouch(sample: MotionSample): SignalFinding? {
        if (sample.deviceId != InputEventBits.DEVICE_ID_VIRTUAL_KEYBOARD) return null
        if (!hasSource(sample.source, InputSourceBits.SOURCE_TOUCHSCREEN)) return null
        return deviceFinding("触屏事件使用了虚拟键盘设备号。", sample)
    }

    private fun keySoftKeyboard(sample: KeySample): SignalFinding? {
        if (!isSoftKeyboard(sample)) return null
        if (matched(sample.deviceName, injectorNames) != null) return null
        return finding(
            signalId = "in.event.device",
            category = category,
            severity = Severity.LOW,
            confidence = 0.4,
            detected = true,
            titleZh = "系统软键盘",
            summaryZh = "按键来自系统软键盘使用的虚拟设备。",
            observedDataZh = "deviceId=${sample.deviceId}，isVirtual=${sample.isDeviceVirtual}。不记录按键码。",
            expectedBaselineZh = "软键盘使用虚拟设备号是正常的，不能据此判作弊。",
            recommendationZh = "不要只凭软键盘的虚拟设备号阻断输入。",
            rawEvidence = mapOf("deviceId" to sample.deviceId.toString(), "isVirtual" to sample.isDeviceVirtual.toString()),
            sourceAttribution = Attribution.INPUT,
        )
    }

    private fun sourceAndTool(sample: MotionSample): SignalFinding? {
        val touch = hasSource(sample.source, InputSourceBits.SOURCE_TOUCHSCREEN)
        val mouse = hasSource(sample.source, InputSourceBits.SOURCE_MOUSE) ||
            sample.toolType == InputEventBits.TOOL_TYPE_MOUSE
        val empty = sample.source == 0 || sample.source == InputSourceBits.SOURCE_ANY
        val unknownTool = touch && sample.toolType == InputEventBits.TOOL_TYPE_UNKNOWN
        val summary = when {
            empty -> "事件来源是空的。"
            mouse && touch -> "同一次事件里既像触屏又像鼠标。"
            mouse -> "这次是鼠标来源，不是触屏手指。"
            unknownTool -> "触屏事件的工具类型是未知。"
            else -> return null
        }
        return finding(
            signalId = "in.event.source",
            category = category,
            severity = Severity.MEDIUM,
            confidence = 0.8,
            detected = true,
            titleZh = "来源与工具类型",
            summaryZh = summary,
            observedDataZh = shortMotion(sample),
            expectedBaselineZh = "手指触摸的来源是触屏，工具类型是手指。鼠标是另一种来源，不是注入证明，也不是真人证明。来源为空或工具类型未知，说明这次事件没有按手指分类。",
            recommendationZh = ADVICE_CLUE,
            rawEvidence = evidence(sample),
            sourceAttribution = Attribution.INPUT,
        )
    }

    private fun pointerTools(sample: MotionSample): SignalFinding? {
        val tools = sample.toolTypes.ifEmpty { listOf(sample.toolType) }
        if (sample.pointerCount < 2 || tools.distinct().size < 2) return null
        return finding(
            signalId = "in.event.pointers",
            category = category,
            severity = Severity.MEDIUM,
            confidence = 0.75,
            detected = true,
            titleZh = "多指工具类型",
            summaryZh = "同一次事件里各指的工具类型不一致。",
            observedDataZh = "pointerCount=${sample.pointerCount}，toolTypes=${tools.joinToString(",") { toolName(it) }}。",
            expectedBaselineZh = "同一次多指触控的各指工具类型通常一致。不一致只是来源线索，不是真人认证。",
            recommendationZh = ADVICE_CLUE,
            rawEvidence = evidence(sample),
            sourceAttribution = Attribution.INPUT,
        )
    }

    private fun obscured(sample: MotionSample): SignalFinding? {
        val full = sample.flags and InputEventBits.FLAG_WINDOW_IS_OBSCURED != 0
        val partial = sample.flags and InputEventBits.FLAG_WINDOW_IS_PARTIALLY_OBSCURED != 0
        if (!full && !partial) return null
        val which = if (full) "事件穿过了被遮挡的区域" else "窗口另有区域被遮挡"
        return finding(
            signalId = "in.event.obscured",
            category = category,
            severity = if (full) Severity.MEDIUM else Severity.LOW,
            confidence = 0.85,
            detected = true,
            titleZh = "窗口遮挡",
            summaryZh = "$which。遮挡不是注入。",
            observedDataZh = shortMotion(sample),
            expectedBaselineZh = "FLAG_WINDOW_IS_OBSCURED 表示触摸穿过上层窗口。FLAG_WINDOW_IS_PARTIALLY_OBSCURED 表示触摸点以外还有遮挡。两者都不是无障碍生成标志。",
            recommendationZh = "遮挡要单独看。不要把它写成注入，也不要忽略点击劫持的可能。",
            rawEvidence = evidence(sample),
            sourceAttribution = Attribution.INPUT,
        )
    }

    private fun obscuredNote(sample: MotionSample): String? {
        val full = sample.flags and InputEventBits.FLAG_WINDOW_IS_OBSCURED != 0
        val partial = sample.flags and InputEventBits.FLAG_WINDOW_IS_PARTIALLY_OBSCURED != 0
        if (!full && !partial) return null
        return if (full) "窗口被遮挡，事件穿过遮挡区域。遮挡不是注入。" else "窗口另有区域被遮挡。遮挡不是注入。"
    }

    private fun emulatorNote(name: String?): String? {
        val hit = matched(name, emulatorNames) ?: return null
        return "设备名含 $hit，像模拟器或虚拟机输入。不能当物理手指基线。"
    }

    private fun weakMotionNotes(current: MotionSample, gesture: List<MotionSample>): List<String> {
        val notes = mutableListOf<String>()
        val up = (current.action and InputEventBits.ACTION_MASK) == InputEventBits.ACTION_UP
        if (up && current.eventTime == current.downTime) {
            notes += "按下和抬起时刻相同。这只是弱观察。"
        }
        val moves = gesture.filter { (it.action and InputEventBits.ACTION_MASK) == InputEventBits.ACTION_MOVE }
        if (moves.size >= 4) {
            if (current.pressureAvailable == true && moves.map { it.pressure }.distinct().size == 1) {
                notes += "连续移动点的压力值相同。压力轴可用，但相同不是阈值。"
            }
            if (current.sizeAvailable == true && moves.map { it.size }.distinct().size == 1) {
                notes += "连续移动点的面积值相同。这不是阈值。"
            }
            if (current.touchMajorAvailable == true && moves.map { it.touchMajor }.distinct().size == 1) {
                notes += "连续移动点的长轴值相同。这不是阈值。"
            }
        }
        return notes
    }

    private fun deviceFinding(summary: String, sample: MotionSample): SignalFinding {
        return finding(
            signalId = "in.event.device",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.86,
            detected = true,
            titleZh = "事件对应的输入设备",
            summaryZh = summary,
            observedDataZh = shortMotion(sample),
            expectedBaselineZh = BASELINE,
            recommendationZh = ADVICE_CLUE,
            rawEvidence = evidence(sample),
            sourceAttribution = Attribution.INPUT,
        )
    }

    private fun isSoftKeyboard(sample: KeySample): Boolean {
        if (matched(sample.deviceName, injectorNames) != null) return false
        val keyboard = hasSource(sample.source, InputSourceBits.SOURCE_KEYBOARD) || sample.source == 0
        return keyboard && (sample.deviceId == InputEventBits.DEVICE_ID_VIRTUAL_KEYBOARD || sample.isDeviceVirtual == true)
    }

    private fun guideGesture(current: MotionSample, gesture: List<MotionSample>): String {
        if (gesture.any { it.pointerCount >= 2 } || current.pointerCount >= 2) return "多指"
        if (!isSettled(current.action)) return ""
        val start = gesture.first()
        val distance = hypot(current.x - start.x, current.y - start.y)
        val duration = current.eventTime - current.downTime
        return when {
            distance >= GUIDE_SWIPE_PX -> "滑动"
            duration >= GUIDE_LONG_MS -> "长按"
            else -> "点击"
        }
    }

    private fun isSettled(action: Int): Boolean {
        val masked = action and InputEventBits.ACTION_MASK
        return masked == InputEventBits.ACTION_UP || masked == InputEventBits.ACTION_POINTER_UP
    }

    private fun capability(sample: MotionSample): String {
        fun axis(label: String, available: Boolean?): String = when (available) {
            null -> "${label}未知"
            false -> "${label}不可用"
            true -> "${label}可用"
        }
        return listOf(
            axis("压力", sample.pressureAvailable),
            axis("面积", sample.sizeAvailable),
            axis("长轴", sample.touchMajorAvailable),
            axis("短轴", sample.touchMinorAvailable),
            "本次${sample.pointerCount}指",
        ).joinToString("，")
    }

    private fun shortMotion(sample: MotionSample): String {
        return "来源=${sourceName(sample.source)}，工具=${toolName(sample.toolType)}，" +
            "设备=${sample.deviceName ?: "（未知）"}，isVirtual=${sample.isDeviceVirtual}，" +
            "flags=0x${sample.flags.toString(16)}。"
    }

    private fun detailMotion(current: MotionSample, gesture: List<MotionSample>): String {
        val duration = current.eventTime - current.downTime
        return "deviceId=${current.deviceId}，deviceName=${current.deviceName ?: "（未知）"}，isVirtual=${current.isDeviceVirtual}，" +
            "source=${sourceName(current.source)}，toolType=${toolName(current.toolType)}，flags=0x${current.flags.toString(16)}，" +
            "pointerCount=${current.pointerCount}，historySize=${current.historySize}，" +
            "pressure=${current.pressure}，size=${current.size}，touchMajor=${current.touchMajor}，touchMinor=${current.touchMinor}，" +
            "点数=${gesture.size}，距按下=${duration}毫秒。设备不支持的轴是不可用，不是异常。"
    }

    private fun evidence(sample: MotionSample): Map<String, String> = mapOf(
        "deviceId" to sample.deviceId.toString(),
        "deviceName" to sample.deviceName.orEmpty(),
        "isVirtual" to sample.isDeviceVirtual.toString(),
        "source" to sample.source.toString(),
        "toolType" to sample.toolType.toString(),
        "flags" to sample.flags.toString(),
        "pointerCount" to sample.pointerCount.toString(),
        "historySize" to sample.historySize.toString(),
        "pressure" to sample.pressure.toString(),
        "pressureAvailable" to sample.pressureAvailable.toString(),
        "size" to sample.size.toString(),
        "sizeAvailable" to sample.sizeAvailable.toString(),
    )

    private fun matched(name: String?, markers: List<String>): String? {
        val lower = name?.lowercase().orEmpty()
        if (lower.isBlank()) return null
        return markers.firstOrNull { it in lower }
    }

    private fun hasSource(sources: Int, bit: Int): Boolean = sources and bit == bit

    private fun sourceName(source: Int): String = when {
        source == 0 -> "0"
        source == InputSourceBits.SOURCE_ANY -> "ANY"
        hasSource(source, InputSourceBits.SOURCE_TOUCHSCREEN) && hasSource(source, InputSourceBits.SOURCE_MOUSE) -> "TOUCHSCREEN|MOUSE"
        hasSource(source, InputSourceBits.SOURCE_TOUCHSCREEN) -> "TOUCHSCREEN"
        hasSource(source, InputSourceBits.SOURCE_MOUSE) -> "MOUSE"
        hasSource(source, InputSourceBits.SOURCE_KEYBOARD) -> "KEYBOARD"
        hasSource(source, InputSourceBits.SOURCE_STYLUS) -> "STYLUS"
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
}
