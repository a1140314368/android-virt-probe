// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.sdk.input

import android.view.KeyEvent
import android.view.MotionEvent
import android.view.Window
import io.virtprobe.core.model.InputNarrative
import io.virtprobe.sdk.VirtProbe

/**
 * 包一层 [Window.Callback]，业务窗口原有的分发逻辑会原样继续。
 *
 * ```
 * window.callback = VirtProbeWindowCallback(window.callback) { trace ->
 *     status.text = trace.verdictZh
 * }
 * ```
 */
class VirtProbeWindowCallback(
    private val base: Window.Callback,
    private val monitor: InputEventMonitor = VirtProbe.inputMonitor(),
    private val onTrace: (InputNarrative) -> Unit = {},
) : Window.Callback by base {
    override fun dispatchTouchEvent(event: MotionEvent): Boolean {
        onTrace(monitor.analyzeMotionEvent(event))
        return base.dispatchTouchEvent(event)
    }

    override fun dispatchKeyEvent(event: KeyEvent): Boolean {
        onTrace(monitor.analyzeKeyEvent(event))
        return base.dispatchKeyEvent(event)
    }
}
