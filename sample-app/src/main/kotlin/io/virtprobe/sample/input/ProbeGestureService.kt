// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.sample.input

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.accessibilityservice.GestureDescription
import android.content.Context
import android.graphics.Path
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityManager

/**
 * 只在测试页按钮按下后，向本应用发送一次手势。
 * 不读取窗口文字，不记录按键，也不改其他应用。
 */
class ProbeGestureService : AccessibilityService() {
    override fun onServiceConnected() {
        running = this
    }

    override fun onUnbind(intent: android.content.Intent?): Boolean {
        if (running === this) running = null
        return super.onUnbind(intent)
    }

    override fun onDestroy() {
        if (running === this) running = null
        super.onDestroy()
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) = Unit

    override fun onInterrupt() = Unit

    private fun dispatch(strokes: List<GestureDescription.StrokeDescription>): Boolean {
        val builder = GestureDescription.Builder()
        strokes.forEach { builder.addStroke(it) }
        return dispatchGesture(builder.build(), null, null)
    }

    companion object {
        private var running: ProbeGestureService? = null

        fun isEnabled(context: Context): Boolean {
            val manager = context.getSystemService(AccessibilityManager::class.java) ?: return false
            return manager.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
                .any { it.resolveInfo?.serviceInfo?.packageName == context.packageName }
        }

        fun tap(x: Float, y: Float): Boolean {
            val service = running ?: return false
            val path = Path().apply { moveTo(x, y) }
            return service.dispatch(listOf(GestureDescription.StrokeDescription(path, 0, 60)))
        }

        fun twoFinger(x: Float, y: Float): Boolean {
            val service = running ?: return false
            val first = Path().apply {
                moveTo(x - 40f, y)
                lineTo(x - 40f, y - 80f)
            }
            val second = Path().apply {
                moveTo(x + 40f, y)
                lineTo(x + 40f, y - 80f)
            }
            return service.dispatch(
                listOf(
                    GestureDescription.StrokeDescription(first, 0, 280),
                    GestureDescription.StrokeDescription(second, 0, 280),
                ),
            )
        }
    }
}
