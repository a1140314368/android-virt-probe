// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.sdk.input

import android.view.InputDevice
import android.view.KeyEvent
import android.view.MotionEvent
import io.virtprobe.core.input.InputEventAnalyzer
import io.virtprobe.core.model.InputEventBits
import io.virtprobe.core.model.InputNarrative
import io.virtprobe.core.model.KeySample
import io.virtprobe.core.model.MotionSample
import io.virtprobe.core.model.Severity
import io.virtprobe.core.model.SignalFinding

/**
 * 把 Android 事件转成纯数据后交给 [InputEventAnalyzer]。
 * 历史点只保留当前手势附近的一小段。软键盘的低敏记录不进入首页线索。
 */
class InputEventMonitor {
    private val lock = Any()
    private val history = ArrayDeque<MotionSample>()
    private var latest: List<SignalFinding> = emptyList()
    private var sequence = 0L

    fun analyzeMotionEvent(event: MotionEvent): InputNarrative {
        val sample = event.toSample()
        val narrative = synchronized(lock) {
            history.add(sample)
            while (history.size > 48) history.removeFirst()
            val produced = InputEventAnalyzer.analyzeMotion(history.toList())
            latest = produced.filter { it.detected && it.severity.atLeast(Severity.MEDIUM) }
            InputEventAnalyzer.narrateMotion(history.toList(), produced).copy(sequence = ++sequence)
        }
        return narrative
    }

    fun analyzeKeyEvent(event: KeyEvent): InputNarrative {
        val sample = event.toSample()
        val narrative = synchronized(lock) {
            val produced = InputEventAnalyzer.analyzeKey(sample)
            val serious = produced.filter { it.detected && it.severity.atLeast(Severity.MEDIUM) }
            if (serious.isNotEmpty()) latest = serious
            InputEventAnalyzer.narrateKey(sample, produced).copy(sequence = ++sequence)
        }
        return narrative
    }

    fun latestDetected(): List<SignalFinding> = synchronized(lock) { latest.toList() }

    private fun MotionEvent.toSample(): MotionSample {
        val index = actionIndex.coerceAtLeast(0)
        val device = try {
            getDevice()
        } catch (_: Throwable) {
            null
        }
        val tools = (0 until pointerCount).map { pointer ->
            try {
                getToolType(pointer)
            } catch (_: Throwable) {
                InputEventBits.TOOL_TYPE_UNKNOWN
            }
        }
        return MotionSample(
            action = actionMasked,
            deviceId = deviceId,
            source = source,
            toolType = tools.getOrElse(index) { InputEventBits.TOOL_TYPE_UNKNOWN },
            flags = flags,
            pressure = axis(index) { getPressure(it) },
            size = axis(index) { getSize(it) },
            touchMajor = axis(index) { getTouchMajor(it) },
            x = axis(index) { getX(it) },
            y = axis(index) { getY(it) },
            eventTime = eventTime,
            downTime = downTime,
            isDeviceVirtual = device?.isVirtual,
            deviceName = device?.name,
            pointerCount = pointerCount,
            toolTypes = tools,
            historySize = historySize,
            touchMinor = axis(index) { getTouchMinor(it) },
            pressureAvailable = axisAvailable(device, MotionEvent.AXIS_PRESSURE, source),
            sizeAvailable = axisAvailable(device, MotionEvent.AXIS_SIZE, source),
            touchMajorAvailable = axisAvailable(device, MotionEvent.AXIS_TOUCH_MAJOR, source),
            touchMinorAvailable = axisAvailable(device, MotionEvent.AXIS_TOUCH_MINOR, source),
            deviceSources = device?.sources ?: source,
            deviceMissing = device == null,
        )
    }

    private fun KeyEvent.toSample(): KeySample {
        val device = try {
            device
        } catch (_: Throwable) {
            null
        }
        return KeySample(
            keyCode = keyCode,
            action = action,
            deviceId = deviceId,
            source = source,
            flags = flags,
            eventTime = eventTime,
            downTime = downTime,
            isDeviceVirtual = device?.isVirtual,
            deviceName = device?.name,
        )
    }

    private fun axis(index: Int, read: (Int) -> Float): Float {
        return try {
            read(index)
        } catch (_: Throwable) {
            0f
        }
    }

    private fun axisAvailable(device: InputDevice?, axis: Int, source: Int): Boolean? {
        if (device == null) return null
        val range = try {
            device.getMotionRange(axis, source) ?: device.getMotionRange(axis)
        } catch (_: Throwable) {
            null
        } ?: return false
        return range.max > range.min
    }
}
