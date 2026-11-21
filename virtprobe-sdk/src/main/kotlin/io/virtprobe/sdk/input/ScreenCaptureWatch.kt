// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.sdk.input

import android.app.Activity
import android.os.Build
import java.lang.reflect.Proxy

/**
 * Android 14 起的屏幕采集回调封装。
 *
 * 平台接口是 `Activity.ScreenCaptureCallback`（屏幕采集回调）。公开 SDK 文档里没有
 * 名为 ScreenRecordingCallback 的类，这里用反射调用同一接口，这样 minSdk 24 的调用方
 * 在旧系统上不会因为类加载失败而崩溃。回调只在注册之后的新采集上触发。
 */
class ScreenCaptureWatch(
    private val activity: Activity,
    private val onState: (Boolean) -> Unit,
) : AutoCloseable {
    @Volatile
    var notified: Boolean = false
        private set

    private var registered = false
    private var callback: Any? = null

    fun register() {
        if (registered || Build.VERSION.SDK_INT < 34) return
        try {
            val callbackClass = Class.forName("android.app.Activity\$ScreenCaptureCallback")
            val proxy = Proxy.newProxyInstance(callbackClass.classLoader, arrayOf(callbackClass)) { self, method, args ->
                when (method.name) {
                    "onScreenCaptured" -> {
                        notified = true
                        onState(true)
                        null
                    }
                    "hashCode" -> System.identityHashCode(self)
                    "equals" -> self === args?.getOrNull(0)
                    "toString" -> "virtprobe.ScreenCaptureCallback"
                    else -> null
                }
            }
            val register = Activity::class.java.getMethod(
                "registerScreenCaptureCallback",
                java.util.concurrent.Executor::class.java,
                callbackClass,
            )
            register.invoke(activity, activity.mainExecutor, proxy)
            callback = proxy
            registered = true
            onState(false)
        } catch (t: Throwable) {
            // Android 14 起该回调需要普通权限 DETECT_SCREEN_CAPTURE。没声明时系统会抛 SecurityException。
            // 这不是「正在录屏」，只表示回调没挂上，扫描继续。
            registered = false
            callback = null
        }
    }

    override fun close() {
        if (!registered || Build.VERSION.SDK_INT < 34) return
        val current = callback ?: return
        runCatching {
            val method = Activity::class.java.getMethod("unregisterScreenCaptureCallback", current.javaClass.interfaces.first())
            method.invoke(activity, current)
        }
        registered = false
        callback = null
    }
}
