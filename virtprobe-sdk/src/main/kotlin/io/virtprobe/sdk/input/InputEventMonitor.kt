// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.sdk.input

import android.view.KeyEvent
import android.view.MotionEvent
import io.virtprobe.core.input.InputEventAnalyzer
import io.virtprobe.core.model.InputEventBits
import io.virtprobe.core.model.InputNarrative
import io.virtprobe.core.model.KeySample
import io.virtprobe.core.model.MotionSample
import io.virtprobe.core.model.SignalFinding

/**
 * 把 Android 事件转成纯数据后交给 [InputEventAnalyzer]。
 * 历史点只保留当前手势附近的一小段，避免一次长按把内存撑大。
 */
class InputEventMonitor {
    private val lock = Any()
    private val history = ArrayDeque<MotionSample>()
    private val downTimes = ArrayDeque<Long>()
    private var latest: List<SignalFinding> = emptyList()

    fun analyzeMotionEvent(event: MotionEvent): InputNarrative {
        val sample = event.toSample()
        val findings = synchronized(lock) {
            history.add(sample)
            while (history.size > 48) history.removeFirst()
            if ((sample.action and InputEventBits.ACTION_MASK) == InputEventBits.ACTION_DOWN) {
                downTimes.add(sample.eventTime)
                while (downTimes.size > 16) downTimes.removeFirst()
            }
            val produced = InputEventAnalyzer.analyzeMotion(history.toList(), downTimes.toList())
            latest = produced.filter { it.detected }
            produced
        }
        return InputEventAnalyzer.narrateMotion(sample, findings)
    }

    fun analyzeKeyEvent(event: KeyEvent): InputNarrative {
        val sample = event.toSample()
        val findings = synchronized(lock) {
            val produced = InputEventAnalyzer.analyzeKey(sample)
            if (produced.any { it.detected }) latest = produced.filter { it.detected }
            produced
        }
        return InputEventAnalyzer.narrateKey(sample, findings)
    }

    fun latestDetected(): List<SignalFinding> = synchronized(lock) { latest.toList() }

    private fun MotionEvent.toSample(): MotionSample {
        val index = actionIndex
        val device = try {
            getDevice()
        } catch (_: Throwable) {
            null
        }
        return MotionSample(
            action = actionMasked,
            deviceId = deviceId,
            source = source,
            toolType = getToolType(index),
            flags = flags,
            pressure = getPressure(index),
            size = getSize(index),
            touchMajor = getTouchMajor(index),
            x = getX(index),
            y = getY(index),
            eventTime = eventTime,
            downTime = downTime,
            isDeviceVirtual = device?.isVirtual,
            deviceName = device?.name,
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
}
