// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.core.virtualdisplay

import io.virtprobe.core.catalog.Attribution
import io.virtprobe.core.catalog.KnownSignals
import io.virtprobe.core.model.DisplayFact
import io.virtprobe.core.model.DisplayFlagBits
import io.virtprobe.core.model.Severity
import io.virtprobe.core.model.SignalCategory
import io.virtprobe.core.model.SignalFinding
import io.virtprobe.core.model.VirtualDisplaySnapshot
import io.virtprobe.core.model.finding

/**
 * 虚拟屏幕、投屏和录屏规则。分类只看公开显示器属性，不依赖任何 GPL 截屏检测实现。
 */
object VirtualDisplayRules {
    private val category = SignalCategory.VIRTUAL_DISPLAY
    private const val PROJECTION_ADVICE =
        "检测到活跃投屏/虚拟副屏，建议对当前页面开启防截屏保护并提示关闭投屏。"

    fun evaluate(snapshot: VirtualDisplaySnapshot): List<SignalFinding> = listOf(
        inventory(snapshot),
        geometry(snapshot),
        screenCapture(snapshot),
        appOps(snapshot),
        routes(snapshot),
        wifiDisplay(snapshot),
    )

    private fun inventory(snapshot: VirtualDisplaySnapshot): SignalFinding {
        val extras = snapshot.displays.filter { !it.isDefault }
        val named = extras.filter { suspiciousName(it.name) }
        val flagged = extras.filter { presentationLike(it.flags) }
        val hit = extras.isNotEmpty()
        val severity = when {
            named.isNotEmpty() -> Severity.HIGH
            flagged.isNotEmpty() -> Severity.MEDIUM
            else -> Severity.LOW
        }
        val described = snapshot.displays.joinToString("；") { display ->
            "id=${display.displayId} 名称=${display.name.ifBlank { "（空）" }} " +
                "flags=${flagText(display.flags)} ${display.widthPx}x${display.heightPx} " +
                "dpi=${display.densityDpi} ${trimFloat(display.refreshHz)}Hz" +
                (if (display.isDefault) " 默认" else " 非默认")
        }.ifBlank { "未枚举到显示器" }
        return finding(
            signalId = "vd.display.inventory",
            category = category,
            severity = severity,
            confidence = if (named.isNotEmpty()) 0.9 else 0.64,
            detected = hit,
            titleZh = "非默认显示器与名称特征",
            summaryZh = when {
                named.isNotEmpty() -> "存在名称像投屏、录屏或虚拟屏的非默认显示器。"
                extras.isNotEmpty() -> "存在非默认显示器，名称本身还不能确定是恶意投屏。"
                else -> "只有默认显示器。"
            },
            observedDataZh = "实际显示器：${described}。",
            expectedBaselineZh = "只拿在手里的真实手机通常只有一块内置默认屏。扩展坞、折叠盖屏也会增加显示器，所以单纯多一块屏只算低敏；名称含 scrcpy、VirtualDisplay、overlay、miracast、cast、wifi-display 才视为投屏或虚拟屏。",
            recommendationZh = if (named.isNotEmpty()) {
                PROJECTION_ADVICE
            } else {
                "出现额外显示器。请看名称和录屏回调；若是扩展坞或盖屏，不要单独阻断。"
            },
            rawEvidence = mapOf(
                "displayCount" to snapshot.displays.size.toString(),
                "extraCount" to extras.size.toString(),
                "suspiciousNames" to named.joinToString(",") { it.name },
            ),
            sourceAttribution = Attribution.DISPLAY,
        )
    }

    private fun geometry(snapshot: VirtualDisplaySnapshot): SignalFinding {
        val odd = snapshot.displays.filter { display ->
            display.densityDpi <= 0 || display.densityDpi > 1000 ||
                display.refreshHz <= 0f || display.widthPx <= 0 || display.heightPx <= 0 ||
                display.widthPx > 8000 || display.heightPx > 8000
        }
        return finding(
            signalId = "vd.display.geometry",
            category = category,
            severity = Severity.MEDIUM,
            confidence = 0.7,
            detected = odd.isNotEmpty(),
            titleZh = "分辨率、DPI 或刷新率异常",
            summaryZh = if (odd.isNotEmpty()) "有显示器的几何参数超出常见真机范围。" else "显示器几何参数落在常见范围内。",
            observedDataZh = if (snapshot.displays.isEmpty()) {
                "没有显示器数据。"
            } else {
                "异常显示器：${odd.joinToString("；") { "id=${it.displayId} ${it.widthPx}x${it.heightPx} dpi=${it.densityDpi} ${it.refreshHz}Hz" }.ifBlank { "无" }}。"
            },
            expectedBaselineZh = "真实手机的密度通常在 120 到 640 dpi，刷新率大于 0 且常见为 60 到 144Hz，单边分辨率不会是 0 或超过 8000。0 刷新率或 0 密度常见于虚拟屏创建参数没填完整。",
            recommendationZh = "几何参数不像物理面板。请结合显示器名称判断是虚拟屏还是采集失败，不要只靠分辨率阻断。",
            rawEvidence = mapOf("oddIds" to odd.joinToString(",") { it.displayId.toString() }),
            sourceAttribution = Attribution.DISPLAY,
        )
    }

    private fun screenCapture(snapshot: VirtualDisplaySnapshot): SignalFinding {
        val notified = snapshot.screenCaptureNotified
        return finding(
            signalId = "vd.capture.callback",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.92,
            detected = notified == true,
            titleZh = "屏幕采集回调",
            summaryZh = when (notified) {
                true -> "Android 14 及以上的屏幕采集回调已经触发。"
                false -> "已注册屏幕采集回调，到目前还没有触发。"
                null -> "本次没有屏幕采集回调状态。"
            },
            observedDataZh = when (notified) {
                true -> "Activity.ScreenCaptureCallback（屏幕采集回调，平台公开名，不是 ScreenRecordingCallback）已回调，表示注册之后发生过截屏或录屏采集。"
                false -> "回调已注册，但本次扫描前没有收到 onScreenCaptured。这不能证明历史上没有人投屏。"
                null -> "未注册 Activity.ScreenCaptureCallback，或系统低于 Android 14（API 34）。当前值=未知。"
            },
            expectedBaselineZh = "没有人截屏或录制时，这个回调不会触发。它只在注册之后的新采集上通知，不能用来回溯注册前已经开始的录屏。",
            recommendationZh = PROJECTION_ADVICE,
            rawEvidence = mapOf("screenCaptureNotified" to (notified?.toString() ?: "unknown")),
            sourceAttribution = Attribution.DISPLAY,
        )
    }

    private fun appOps(snapshot: VirtualDisplaySnapshot): SignalFinding {
        val media = snapshot.projectMediaMode
        val audio = snapshot.projectAudioMode
        val mediaOn = media.equals("MODE_ALLOWED", ignoreCase = true)
        val audioOn = audio.equals("MODE_ALLOWED", ignoreCase = true)
        val hit = mediaOn || audioOn
        return finding(
            signalId = "vd.appops.projection",
            category = category,
            severity = Severity.MEDIUM,
            confidence = 0.74,
            detected = hit,
            titleZh = "本应用的媒体/音频投射 AppOp",
            summaryZh = if (hit) "本应用自己的投射操作处于允许状态。" else "本应用的投射 AppOp 未处于允许状态。",
            observedDataZh = "OPSTR_PROJECT_MEDIA=${media ?: "未读取（低于 Android 10 或无权限）"}，" +
                "OPSTR_PROJECT_AUDIO=${audio ?: "未读取（低于 Android 12 或无权限）"}。",
            expectedBaselineZh = "这两个 AppOp 描述的是本应用自己能不能投射媒体或音频，不是全系统有没有别的应用在录屏。普通应用在没有发起 MediaProjection 时通常不是 MODE_ALLOWED。",
            recommendationZh = "本应用处于投射允许状态。如果业务本身不投屏，应停止 MediaProjection，并对敏感页面打开 FLAG_SECURE。",
            rawEvidence = mapOf(
                "projectMedia" to media.orEmpty(),
                "projectAudio" to audio.orEmpty(),
            ),
            sourceAttribution = Attribution.DISPLAY,
        )
    }

    private fun routes(snapshot: VirtualDisplaySnapshot): SignalFinding {
        val selected = snapshot.selectedRemoteRoute
        val hit = !selected.isNullOrBlank()
        val named = hit && suspiciousName(selected)
        return finding(
            signalId = "vd.route.remote",
            category = category,
            severity = if (named) Severity.HIGH else Severity.MEDIUM,
            confidence = if (named) 0.9 else 0.72,
            detected = hit,
            titleZh = "外部媒体路由",
            summaryZh = if (hit) "MediaRouter 当前选中了远程播放路由。" else "没有选中远程媒体路由。",
            observedDataZh = "当前选中的远程路由=${selected ?: "（无）"}。可见远程路由：${snapshot.remoteRouteNames.joinToString("，").ifBlank { "无" }}。",
            expectedBaselineZh = "手机本地扬声器是本地路由。选中 Chromecast、Miracast、无线显示等远程路由，说明画面或声音正在被送到外部设备。",
            recommendationZh = PROJECTION_ADVICE,
            rawEvidence = mapOf(
                "selected" to selected.orEmpty(),
                "routes" to snapshot.remoteRouteNames.joinToString("|"),
            ),
            sourceAttribution = Attribution.DISPLAY,
        )
    }

    private fun wifiDisplay(snapshot: VirtualDisplaySnapshot): SignalFinding {
        val on = snapshot.wifiDisplayOn
        return finding(
            signalId = "vd.setting.wifi_display",
            category = category,
            severity = Severity.MEDIUM,
            confidence = 0.7,
            detected = on == true,
            titleZh = "系统无线显示开关",
            summaryZh = if (on == true) "Settings.Global.WIFI_DISPLAY_ON 为开启。" else "无线显示开关未报告为开启。",
            observedDataZh = "WIFI_DISPLAY_ON=${when (on) { true -> "1"; false -> "0"; null -> "未读取" }}。",
            expectedBaselineZh = "没有打开无线显示时，这个全局设置应为 0。它表示系统层的 Miracast/无线显示开关，和某一块虚拟屏是否由本应用创建不是同一件事。",
            recommendationZh = "系统无线显示已打开，建议提示用户关闭投屏，并对当前页面开启防截屏保护。",
            rawEvidence = mapOf("wifiDisplayOn" to (on?.toString() ?: "unknown")),
            sourceAttribution = Attribution.DISPLAY,
        )
    }

    private fun suspiciousName(name: String?): Boolean {
        val lower = name?.lowercase()?.trim().orEmpty()
        if (lower.isEmpty()) return false
        return KnownSignals.DISPLAY_NAME_MARKERS.any { marker -> marker in lower }
    }

    private fun presentationLike(flags: Int): Boolean {
        return flags and DisplayFlagBits.FLAG_PRESENTATION != 0 ||
            flags and DisplayFlagBits.FLAG_PRIVATE != 0
    }

    private fun flagText(flags: Int): String {
        val names = mutableListOf<String>()
        if (flags and DisplayFlagBits.FLAG_SECURE != 0) names += "SECURE"
        if (flags and DisplayFlagBits.FLAG_PRIVATE != 0) names += "PRIVATE"
        if (flags and DisplayFlagBits.FLAG_PRESENTATION != 0) names += "PRESENTATION"
        if (names.isEmpty()) names += "0x${flags.toString(16)}"
        return names.joinToString("|")
    }

    private fun trimFloat(value: Float): String {
        val rounded = (value * 10).toInt() / 10.0
        return rounded.toString()
    }
}
