// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.core.input

import io.virtprobe.core.catalog.Attribution
import io.virtprobe.core.catalog.KnownSignals
import io.virtprobe.core.model.InputAuditSnapshot
import io.virtprobe.core.model.InputDeviceFact
import io.virtprobe.core.model.InputSourceBits
import io.virtprobe.core.model.NodeVisibility
import io.virtprobe.core.model.Severity
import io.virtprobe.core.model.SignalCategory
import io.virtprobe.core.model.SignalFinding
import io.virtprobe.core.model.finding
import io.virtprobe.core.parse.ProcText

/**
 * 静态输入设备、原生输入节点、无障碍与自动化框架。
 * 实时事件的运动学在 [InputEventAnalyzer]。
 */
object InputDeviceRules {
    private val category = SignalCategory.INPUT

    fun evaluate(snapshot: InputAuditSnapshot): List<SignalFinding> = listOf(
        inventory(snapshot),
        virtualTouch(snapshot),
        zeroIds(snapshot),
        shape(snapshot),
        procBus(snapshot),
        uinput(snapshot),
        accessibility(snapshot),
        automation(snapshot),
        instrumentation(snapshot),
    )

    private fun inventory(snapshot: InputAuditSnapshot): SignalFinding {
        val described = snapshot.devices.joinToString("；") { device ->
            "id=${device.id} name=${device.name.ifBlank { "（空）" }} virtual=${device.isVirtual} " +
                "external=${device.isExternal} vid=${device.vendorId} pid=${device.productId} " +
                "sources=${sourceText(device.sources)}"
        }.ifBlank { "没有枚举到 InputDevice" }
        return finding(
            signalId = "in.dev.inventory",
            category = category,
            severity = Severity.INFO,
            confidence = 0.0,
            detected = false,
            titleZh = "输入设备盘点",
            summaryZh = "本项只陈列设备，具体异常看后面的虚拟触屏、厂商号和形态规则。",
            observedDataZh = "实际设备 ${snapshot.devices.size} 个：$described。",
            expectedBaselineZh = "真实手机至少有一块 isVirtual=false 的触摸屏，厂商号和产品号通常非 0。系统软键盘可能另有一个虚拟设备，那一项单独作为低敏提示。",
            recommendationZh = "盘点本身不产生处置。请看同组的虚拟触屏和运动学结论。",
            rawEvidence = mapOf("count" to snapshot.devices.size.toString()),
            sourceAttribution = Attribution.INPUT,
        )
    }

    private fun virtualTouch(snapshot: InputAuditSnapshot): SignalFinding {
        val touches = snapshot.devices.filter { hasSource(it.sources, InputSourceBits.SOURCE_TOUCHSCREEN) && it.isVirtual }
        val named = snapshot.devices.filter { device ->
            val name = device.name.lowercase()
            KnownSignals.INPUT_NAME_MARKERS.any { marker -> marker in name } &&
                (device.isVirtual || hasSource(device.sources, InputSourceBits.SOURCE_TOUCHSCREEN) || "uinput" in name || "scrcpy" in name)
        }
        val hits = (touches + named).distinctBy { it.id }
        return finding(
            signalId = "in.dev.virtual",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.9,
            detected = hits.isNotEmpty(),
            titleZh = "虚拟或远控输入设备",
            summaryZh = if (hits.isNotEmpty()) "存在虚拟触摸屏，或设备名带有 uinput、scrcpy、goldfish 等远控特征。" else "没有虚拟触摸屏或已知远控输入设备名。",
            observedDataZh = if (hits.isEmpty()) {
                "已检查 ${snapshot.devices.size} 个设备，没有虚拟触摸屏，也没有远控特征名。"
            } else {
                "命中设备：${hits.joinToString("；") { "id=${it.id} name=${it.name} virtual=${it.isVirtual} sources=${sourceText(it.sources)}" }}。"
            },
            expectedBaselineZh = "真实手指触控应来自物理触控芯片 isVirtual=false。uinput、goldfish、ranchu、virtio、scrcpy、vtouch、vbox、genymotion、bluestacks 都不是手机自带的触摸芯片。",
            recommendationZh = "输入设备像远程注入或模拟器触摸，建议拒绝依赖这次触控完成的敏感操作，并要求物理触摸复核。",
            rawEvidence = mapOf("hits" to hits.joinToString(",") { "${it.id}:${it.name}" }),
            sourceAttribution = Attribution.INPUT,
        )
    }

    private fun zeroIds(snapshot: InputAuditSnapshot): SignalFinding {
        val hits = snapshot.devices.filter { device ->
            device.vendorId == 0 && device.productId == 0 &&
                (hasSource(device.sources, InputSourceBits.SOURCE_TOUCHSCREEN) || device.isVirtual.not() && hasSource(device.sources, InputSourceBits.SOURCE_MOUSE))
        }
        val touch = hits.filter { hasSource(it.sources, InputSourceBits.SOURCE_TOUCHSCREEN) }
        return finding(
            signalId = "in.dev.ids",
            category = category,
            severity = if (touch.isNotEmpty()) Severity.HIGH else Severity.MEDIUM,
            confidence = 0.78,
            detected = hits.isNotEmpty(),
            titleZh = "厂商号与产品号同时为 0",
            summaryZh = if (hits.isNotEmpty()) "触摸屏或鼠标的 vendorId 和 productId 都是 0。" else "没有发现厂商号和产品号同时为 0 的触屏或鼠标。",
            observedDataZh = if (hits.isEmpty()) {
                "已检查设备的 vendorId/productId，触屏和鼠标没有 0/0 组合。"
            } else {
                "0/0 设备：${hits.joinToString("；") { "id=${it.id} name=${it.name} sources=${sourceText(it.sources)}" }}。"
            },
            expectedBaselineZh = "物理触控芯片会暴露 USB 或内部总线的厂商号和产品号，不应长期是 0 和 0。虚拟设备经常把这两项留空。仅软键盘不在本项范围内。",
            recommendationZh = "触控设备缺少真实厂商标识，建议按虚拟输入处理本次敏感操作。",
            rawEvidence = mapOf("hits" to hits.joinToString(",") { it.name }),
            sourceAttribution = Attribution.INPUT,
        )
    }

    private fun shape(snapshot: InputAuditSnapshot): SignalFinding {
        if (snapshot.devices.isEmpty()) {
            return finding(
                signalId = "in.dev.shape",
                category = category,
                severity = Severity.MEDIUM,
                confidence = 0.6,
                detected = false,
                titleZh = "缺少物理触摸屏",
                summaryZh = "没有设备列表，无法判断是没有触摸屏还是枚举失败。",
                observedDataZh = "InputDevice 列表为空。",
                expectedBaselineZh = "真实手机应有非虚拟触摸屏。只有鼠标和键盘、没有触摸屏，更像模拟器或远控桌面。列表为空时不判命中。",
                recommendationZh = "请重新枚举输入设备。",
                rawEvidence = emptyMap(),
                sourceAttribution = Attribution.INPUT,
            )
        }
        val physicalTouch = snapshot.devices.any {
            hasSource(it.sources, InputSourceBits.SOURCE_TOUCHSCREEN) && !it.isVirtual
        }
        val pointerOnly = snapshot.devices.any {
            hasSource(it.sources, InputSourceBits.SOURCE_MOUSE) || hasSource(it.sources, InputSourceBits.SOURCE_KEYBOARD)
        }
        val hit = !physicalTouch && pointerOnly
        return finding(
            signalId = "in.dev.shape",
            category = category,
            severity = Severity.MEDIUM,
            confidence = 0.74,
            detected = hit,
            titleZh = "缺少物理触摸屏",
            summaryZh = if (hit) "没有非虚拟触摸屏，却存在键鼠。" else "存在非虚拟触摸屏，或当前没有键鼠可对照。",
            observedDataZh = "非虚拟触摸屏=$physicalTouch，存在键鼠=$pointerOnly。",
            expectedBaselineZh = "手机形态的真机应有物理触摸屏。只有键盘和鼠标、没有触摸屏，是桌面模拟器或远程控制的常见形态。",
            recommendationZh = "设备形态不像手机触控，建议结合模拟器规则决定是否限制敏感操作。",
            rawEvidence = mapOf(
                "physicalTouch" to physicalTouch.toString(),
                "pointer" to pointerOnly.toString(),
            ),
            sourceAttribution = Attribution.INPUT,
        )
    }

    private fun procBus(snapshot: InputAuditSnapshot): SignalFinding {
        val text = snapshot.procBusInputText
        val parsed = if (text.isNullOrBlank()) emptyList() else ProcText.parseInputDevices(text)
        val hits = parsed.filter { device ->
            val name = device.name.lowercase()
            KnownSignals.INPUT_NAME_MARKERS.any { it in name }
        }
        val denied = snapshot.procBusReadError?.contains("EACCES", ignoreCase = true) == true ||
            snapshot.procBusReadError?.contains("Permission", ignoreCase = true) == true
        return finding(
            signalId = "in.native.proc",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.86,
            detected = hits.isNotEmpty(),
            titleZh = "内核输入设备表",
            summaryZh = if (hits.isNotEmpty()) "/proc/bus/input/devices 出现模拟器或注入设备名。" else "内核输入设备表没有已知虚拟设备名，或当前不可读。",
            observedDataZh = when {
                text == null -> "未读取 /proc/bus/input/devices。错误=${snapshot.procBusReadError ?: "无"}。"
                denied -> "读取被拒绝（${snapshot.procBusReadError}）。SELinux 不允许时只记录原始错误，不算命中。"
                else -> "解析到 ${parsed.size} 个内核输入设备。命中：${hits.joinToString("；") { "${it.name} handlers=${it.handlers}" }.ifBlank { "无" }}。"
            },
            expectedBaselineZh = "真机触摸屏在内核里有具体芯片名。goldfish、ranchu、uinput、qwerty2 这类名字常见于模拟器。权限被拒绝必须原样记录，不能推测成攻击。",
            recommendationZh = "内核输入子系统暴露虚拟设备，建议拒绝本次敏感输入并要求物理触摸复核。",
            rawEvidence = mapOf(
                "parsed" to parsed.size.toString(),
                "error" to snapshot.procBusReadError.orEmpty(),
                "hits" to hits.joinToString(",") { it.name },
            ),
            sourceAttribution = Attribution.INPUT,
        )
    }

    private fun uinput(snapshot: InputAuditSnapshot): SignalFinding {
        val present = snapshot.uinputVisibility == NodeVisibility.PRESENT
        return finding(
            signalId = "in.native.uinput",
            category = category,
            severity = Severity.MEDIUM,
            confidence = 0.66,
            detected = present,
            titleZh = "uinput 节点可见性",
            summaryZh = when (snapshot.uinputVisibility) {
                NodeVisibility.PRESENT -> "/dev/uinput 对当前进程可见。"
                NodeVisibility.ABSENT -> "/dev/uinput 不存在。"
                NodeVisibility.PERMISSION_DENIED -> "/dev/uinput 存在与否无法确认，访问被拒绝。"
                NodeVisibility.UNKNOWN -> "尚未探测 /dev/uinput。"
            },
            observedDataZh = "uinput=${snapshot.uinputVisibility}。/dev/input/event 节点：${snapshot.inputEventNodes.joinToString("，").ifBlank { "未列出" }}。" +
                (if (snapshot.inputNodeError.isNullOrBlank()) "" else "节点探测错误=${snapshot.inputNodeError}。"),
            expectedBaselineZh = "普通应用在 SELinux 下通常不能打开 /dev/uinput。节点可见说明进程有能力或视野看到用户态输入注入接口，但可见不等于正在注入。权限拒绝要记在原始证据里，不能当成异常命中。",
            recommendationZh = "uinput 可见。建议提高输入校验等级，并结合实时事件的 deviceId 与压力变化判断是不是正在注入。",
            rawEvidence = mapOf(
                "uinput" to snapshot.uinputVisibility.name,
                "eventNodes" to snapshot.inputEventNodes.joinToString(","),
                "error" to snapshot.inputNodeError.orEmpty(),
            ),
            sourceAttribution = Attribution.INPUT,
        )
    }

    private fun accessibility(snapshot: InputAuditSnapshot): SignalFinding {
        val services = snapshot.enabledAccessibilityServices.filter { it.isNotBlank() }
        return finding(
            signalId = "in.a11y.enabled",
            category = category,
            severity = Severity.LOW,
            confidence = 0.5,
            detected = services.isNotEmpty(),
            titleZh = "已启用的无障碍服务",
            summaryZh = if (services.isNotEmpty()) "系统启用了无障碍服务。密码管理器和读屏也会如此，单独出现只算低敏。" else "没有启用中的无障碍服务。",
            observedDataZh = "ENABLED_ACCESSIBILITY_SERVICES=${services.joinToString("；").ifBlank { "（空）" }}。",
            expectedBaselineZh = "没有开启无障碍时，这个安全设置应为空。真机上的读屏、自动填充也可能启用无障碍，所以不能只凭「有服务」阻断，要看是不是已知自动化包，以及事件是否带无障碍生成标志。",
            recommendationZh = "存在无障碍服务。请核对服务包名；若同时出现机械点击节律或无障碍事件标志，再拒绝敏感操作。",
            rawEvidence = mapOf("services" to services.joinToString("|")),
            sourceAttribution = Attribution.INPUT,
        )
    }

    private fun automation(snapshot: InputAuditSnapshot): SignalFinding {
        val installed = snapshot.installedAutomationPackages.distinct()
        val running = snapshot.runningProcessNames.filter { process ->
            KnownSignals.AUTOMATION_PACKAGES.any { pkg -> process == pkg || process.startsWith("$pkg:") || process.startsWith("$pkg.") }
        }
        val hit = installed.isNotEmpty() || running.isNotEmpty()
        return finding(
            signalId = "in.auto.packages",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.88,
            detected = hit,
            titleZh = "自动化与点击器组件",
            summaryZh = if (hit) "安装或正在运行 UiAutomator、Appium、Auto.js、Tasker、按键精灵等自动化组件。" else "未发现已知自动化组件。",
            observedDataZh = "已安装：${installed.joinToString("，").ifBlank { "无" }}。进程：${running.joinToString("，").ifBlank { "无" }}。",
            expectedBaselineZh = "普通用户的业务进程里不应驻留 Appium、UiAutomator、Auto.js、按键精灵或同类点击器。Tasker、MacroDroid 也可能被本人合法使用，但仍说明当前环境具备脚本输入能力。",
            recommendationZh = "环境具备自动化输入能力，建议对点击类敏感操作要求物理触摸复核。",
            rawEvidence = mapOf(
                "installed" to installed.joinToString(","),
                "running" to running.joinToString(","),
            ),
            sourceAttribution = Attribution.INPUT,
        )
    }

    private fun instrumentation(snapshot: InputAuditSnapshot): SignalFinding {
        val name = snapshot.instrumentationClassName.orEmpty()
        val hit = name.isNotEmpty() && name != "android.app.Instrumentation"
        return finding(
            signalId = "in.instrumentation",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.85,
            detected = hit,
            titleZh = "插桩 Instrumentation",
            summaryZh = if (hit) "当前进程的 Instrumentation 不是框架默认实现。" else "Instrumentation 是框架默认类，或未能反射到。",
            observedDataZh = "实际类名=${name.ifBlank { "（未能读取）" }}。",
            expectedBaselineZh = "普通应用的 ActivityThread.mInstrumentation 类型是 android.app.Instrumentation。UiAutomator 和测试运行器会换成自己的子类。反射被系统限制时只记录失败，不算命中。",
            recommendationZh = "进程处于测试插桩之下，建议拒绝生产环境的敏感操作。",
            rawEvidence = mapOf("instrumentation" to name),
            sourceAttribution = Attribution.INPUT,
        )
    }

    private fun hasSource(sources: Int, source: Int): Boolean = sources and source == source

    private fun sourceText(sources: Int): String {
        val names = mutableListOf<String>()
        if (hasSource(sources, InputSourceBits.SOURCE_TOUCHSCREEN)) names += "TOUCHSCREEN"
        if (hasSource(sources, InputSourceBits.SOURCE_MOUSE)) names += "MOUSE"
        if (hasSource(sources, InputSourceBits.SOURCE_KEYBOARD)) names += "KEYBOARD"
        if (hasSource(sources, InputSourceBits.SOURCE_DPAD)) names += "DPAD"
        if (hasSource(sources, InputSourceBits.SOURCE_STYLUS)) names += "STYLUS"
        if (names.isEmpty()) names += "0x${sources.toString(16)}"
        return names.joinToString("|")
    }
}
