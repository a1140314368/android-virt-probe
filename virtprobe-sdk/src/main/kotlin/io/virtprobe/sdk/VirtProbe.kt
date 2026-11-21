// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.sdk

import android.app.Activity
import android.content.Context
import android.view.KeyEvent
import android.view.MotionEvent
import io.virtprobe.core.engine.EngineConfig
import io.virtprobe.core.engine.ProbeEngine
import io.virtprobe.core.model.InputNarrative
import io.virtprobe.core.model.ProbeReport
import io.virtprobe.core.model.ProbeSnapshots
import io.virtprobe.sdk.collect.ConsistencyCollector
import io.virtprobe.sdk.collect.ContainerCollector
import io.virtprobe.sdk.collect.DisplayCollector
import io.virtprobe.sdk.collect.EmulatorCollector
import io.virtprobe.sdk.collect.InputCollector
import io.virtprobe.sdk.collect.RuntimeCollector
import io.virtprobe.sdk.input.InputEventMonitor
import io.virtprobe.sdk.input.ScreenCaptureWatch
import io.virtprobe.sdk.native.NativeBridge
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * 虚拟环境探针的统一入口。
 *
 * ```
 * val report = VirtProbe.scan(context)
 * textView.text = report.conclusionTitleZh
 * ```
 *
 * 采集在本模块完成，判定在 `virtprobe-core` 完成。某一维采集失败不会让整次扫描崩溃，
 * 失败原因会写进该维快照的错误字段。
 */
object VirtProbe {
    private val executor: ExecutorService = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "virtprobe-scan").apply { isDaemon = true }
    }
    private val monitor = InputEventMonitor()

    @Volatile
    private var screenCaptureNotified: Boolean? = null

    fun inputMonitor(): InputEventMonitor = monitor

    /** 同步扫描。传感器采样默认最多 200 毫秒，并且使用独立线程，主线程调用也不会和传感器回调互相卡死。 */
    fun scan(context: Context, config: VirtProbeConfig = VirtProbeConfig()): ProbeReport {
        val app = context.applicationContext
        val native = NativeBridge.safeCollect()
        val samples = if (config.enableEmulator || config.enableConsistency) {
            runCatching { EmulatorCollector.sampleForScan(app, config.sensorSampleTimeoutMs) }.getOrDefault(emptyList())
        } else {
            emptyList()
        }
        val emulator = if (config.enableEmulator) {
            runCatching { EmulatorCollector.collect(app, native, 0) }.getOrNull()?.copy(accelerometerSamples = samples)
        } else {
            null
        }
        val snapshots = ProbeSnapshots(
            emulator = emulator,
            container = if (config.enableContainer) runCatching { ContainerCollector.collect(app, native) }.getOrNull() else null,
            virtualDisplay = if (config.enableVirtualDisplay) {
                runCatching { DisplayCollector.collect(app, screenCaptureNotified) }.getOrNull()
            } else {
                null
            },
            consistency = if (config.enableConsistency) {
                runCatching { ConsistencyCollector.collect(app, native, samples) }.getOrNull()
            } else {
                null
            },
            input = if (config.enableInput) runCatching { InputCollector.collect(app, native) }.getOrNull() else null,
            runtime = if (config.enableRuntime) runCatching { RuntimeCollector.collect(app, native) }.getOrNull() else null,
            liveInputFindings = if (config.includeRecentInput) monitor.latestDetected() else emptyList(),
        )
        return ProbeEngine.evaluate(
            snapshots,
            EngineConfig(
                enableEmulator = config.enableEmulator,
                enableContainer = config.enableContainer,
                enableVirtualDisplay = config.enableVirtualDisplay,
                enableConsistency = config.enableConsistency,
                enableInput = config.enableInput,
                enableRuntime = config.enableRuntime,
            ),
        )
    }

    /**
     * 异步扫描。回调发生在探针自己的后台线程上，更新界面前请切回主线程。
     */
    fun scanAsync(
        context: Context,
        config: VirtProbeConfig = VirtProbeConfig(),
        callback: (ProbeReport) -> Unit,
    ) {
        val app = context.applicationContext
        executor.execute { callback(scan(app, config)) }
    }

    fun analyzeMotionEvent(event: MotionEvent): InputNarrative = monitor.analyzeMotionEvent(event)

    fun analyzeKeyEvent(event: KeyEvent): InputNarrative = monitor.analyzeKeyEvent(event)

    /**
     * 注册 Android 14（API 34）的 [Activity.ScreenCaptureCallback]。
     * 平台公开名称是屏幕采集回调，不是 ScreenRecordingCallback。低于 API 34 时注册为空操作。
     */
    fun attachScreenCaptureWatch(activity: Activity): ScreenCaptureWatch {
        val watch = ScreenCaptureWatch(activity) { fired -> screenCaptureNotified = fired }
        watch.register()
        return watch
    }

    }
