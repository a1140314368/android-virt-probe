// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.core.emulator

import io.virtprobe.core.catalog.Attribution
import io.virtprobe.core.catalog.KnownSignals
import io.virtprobe.core.model.AccelSample
import io.virtprobe.core.model.BLOCK_SENSITIVE_RECOMMENDATION_ZH
import io.virtprobe.core.model.EmulatorSnapshot
import io.virtprobe.core.model.Severity
import io.virtprobe.core.model.SignalCategory
import io.virtprobe.core.model.SignalFinding
import io.virtprobe.core.model.finding
import io.virtprobe.core.model.getTrimmed
import io.virtprobe.core.parse.ProcText
import kotlin.math.sqrt

/**
 * 模拟器、虚拟机、云手机与转译层规则。
 * 只消费 [EmulatorSnapshot]，因此可以在没有 Android SDK 的 JVM 上单测。
 */
object EmulatorRules {
    private val category = SignalCategory.EMULATOR

    fun evaluate(snapshot: EmulatorSnapshot): List<SignalFinding> = listOf(
        qemuProperties(snapshot),
        identity(snapshot),
        services(snapshot),
        files(snapshot),
        packages(snapshot),
        graphics(snapshot),
        hypervisor(snapshot),
        translation(snapshot),
        sensors(snapshot),
        accelerometer(snapshot),
        battery(snapshot),
        cloudNic(snapshot),
    )

    private fun qemuProperties(snapshot: EmulatorSnapshot): SignalFinding {
        val props = snapshot.nativeProperties
        val kernel = props.getTrimmed("ro.kernel.qemu")
        val boot = props.getTrimmed("ro.boot.qemu")
        val avd = props.getTrimmed("ro.boot.qemu.avd_name")
        val gles = props.getTrimmed("ro.kernel.qemu.gles")
        val qemud = props.getTrimmed("ro.kernel.android.qemud")
        val hit = affirmative(kernel) || affirmative(boot) || avd.isNotEmpty() || affirmative(gles) || qemud.isNotEmpty()
        return finding(
            signalId = "emu.prop.qemu",
            category = category,
            severity = Severity.CRITICAL,
            confidence = 0.98,
            detected = hit,
            titleZh = "QEMU 内核与启动属性",
            summaryZh = if (hit) "系统属性暴露 QEMU 或模拟器启动特征。" else "未发现 QEMU 内核或启动属性。",
            observedDataZh = "实际读取：ro.kernel.qemu=${show(kernel)}，ro.boot.qemu=${show(boot)}，" +
                "ro.boot.qemu.avd_name=${show(avd)}，ro.kernel.qemu.gles=${show(gles)}，" +
                "ro.kernel.android.qemud=${show(qemud)}。属性来源：${snapshot.propertyOrigin}。",
            expectedBaselineZh = "真实物理手机不应由 QEMU 启动，ro.kernel.qemu 与 ro.boot.qemu 应为空或 0，且不应出现 AVD（模拟器虚拟设备）名称。",
            recommendationZh = BLOCK_SENSITIVE_RECOMMENDATION_ZH,
            rawEvidence = mapOf(
                "ro.kernel.qemu" to kernel,
                "ro.boot.qemu" to boot,
                "ro.boot.qemu.avd_name" to avd,
                "ro.kernel.qemu.gles" to gles,
                "ro.kernel.android.qemud" to qemud,
                "propertyOrigin" to snapshot.propertyOrigin,
            ),
            sourceAttribution = Attribution.EMULATOR,
        )
    }

    private fun identity(snapshot: EmulatorSnapshot): SignalFinding {
        val hardware = firstNonBlank(snapshot.nativeProperties.getTrimmed("ro.hardware"), snapshot.javaBuild.getTrimmed("HARDWARE"))
        val model = firstNonBlank(snapshot.nativeProperties.getTrimmed("ro.product.model"), snapshot.javaBuild.getTrimmed("MODEL"))
        val brand = firstNonBlank(snapshot.nativeProperties.getTrimmed("ro.product.brand"), snapshot.javaBuild.getTrimmed("BRAND"))
        val product = firstNonBlank(snapshot.nativeProperties.getTrimmed("ro.product.name"), snapshot.javaBuild.getTrimmed("PRODUCT"))
        val fingerprint = firstNonBlank(
            snapshot.nativeProperties.getTrimmed("ro.build.fingerprint"),
            snapshot.javaBuild.getTrimmed("FINGERPRINT"),
        )
        val characteristics = snapshot.nativeProperties.getTrimmed("ro.build.characteristics")
        val flavor = snapshot.nativeProperties.getTrimmed("ro.build.flavor")
        val blob = listOf(hardware, model, brand, product, fingerprint, characteristics, flavor).joinToString(" ").lowercase()
        val hardwareHit = hardware.lowercase() in KnownSignals.HARDWARE_EQUALS ||
            KnownSignals.HARDWARE_EQUALS.any { hardware.lowercase().contains(it) && it.length >= 4 }
        val marker = KnownSignals.IDENTITY_MARKERS.filter { it in blob }
        val characteristicHit = characteristics.split(',', ' ').any { it.equals("emulator", ignoreCase = true) }
        val cloud = KnownSignals.CLOUD_MARKERS.filter { it in blob }
        val hit = hardwareHit || marker.isNotEmpty() || characteristicHit || cloud.isNotEmpty()
        val severity = when {
            hardwareHit || characteristicHit || "goldfish" in blob || "ranchu" in blob || "sdk_gphone" in blob -> Severity.CRITICAL
            cloud.isNotEmpty() -> Severity.HIGH
            else -> Severity.HIGH
        }
        return finding(
            signalId = "emu.prop.identity",
            category = category,
            severity = severity,
            confidence = 0.93,
            detected = hit,
            titleZh = "硬件、机型与指纹身份",
            summaryZh = if (hit) "机型身份字符串落入已知模拟器、虚拟机或云手机特征。" else "机型身份字符串未落入已知虚拟设备特征。",
            observedDataZh = "实际读取：hardware=${show(hardware)}，brand=${show(brand)}，model=${show(model)}，" +
                "product=${show(product)}，characteristics=${show(characteristics)}，fingerprint=${show(fingerprint)}。" +
                (if (marker.isEmpty() && cloud.isEmpty()) "" else "命中特征：${(marker + cloud).distinct().joinToString("、")}。"),
            expectedBaselineZh = "真实物理手机的 ro.hardware 应为具体 SoC（片上系统）或机型代号，不应为 goldfish、ranchu、vbox、cutf_cvm、crosvm；" +
                "ro.build.characteristics 不应包含 emulator；指纹与型号不应出现 sdk_gphone、generic/sdk、Genymotion、BlueStacks、夜神、雷电、MuMu 等字样。",
            recommendationZh = BLOCK_SENSITIVE_RECOMMENDATION_ZH,
            rawEvidence = mapOf(
                "hardware" to hardware,
                "brand" to brand,
                "model" to model,
                "product" to product,
                "characteristics" to characteristics,
                "fingerprint" to fingerprint,
                "markers" to (marker + cloud).distinct().joinToString(","),
            ),
            sourceAttribution = Attribution.EMULATOR,
        )
    }

    private fun services(snapshot: EmulatorSnapshot): SignalFinding {
        val running = KnownSignals.QEMU_SERVICE_KEYS.mapNotNull { key ->
            val value = snapshot.nativeProperties.getTrimmed(key)
            if (value.equals("running", ignoreCase = true) || value.equals("restarting", ignoreCase = true)) {
                "$key=$value"
            } else {
                null
            }
        }
        return finding(
            signalId = "emu.prop.services",
            category = category,
            severity = Severity.CRITICAL,
            confidence = 0.96,
            detected = running.isNotEmpty(),
            titleZh = "QEMU 与虚拟化 init 服务",
            summaryZh = if (running.isNotEmpty()) "init 服务列表中有模拟器配套服务处于 running。" else "未发现处于 running 的模拟器 init 服务。",
            observedDataZh = if (running.isEmpty()) {
                "实际读取：" + KnownSignals.QEMU_SERVICE_KEYS.joinToString("，") { key ->
                    "$key=${show(snapshot.nativeProperties.getTrimmed(key))}"
                } + "。"
            } else {
                "实际处于 running/restarting 的服务：${running.joinToString("，")}。"
            },
            expectedBaselineZh = "真实物理手机没有 qemu-props、qemud、goldfish-logcat、goldfish-setup、vbox86-setup 这类 init 服务，对应属性应为空或 stopped。",
            recommendationZh = BLOCK_SENSITIVE_RECOMMENDATION_ZH,
            rawEvidence = KnownSignals.QEMU_SERVICE_KEYS.associateWith { snapshot.nativeProperties.getTrimmed(it) },
            sourceAttribution = Attribution.EMULATOR,
        )
    }

    private fun files(snapshot: EmulatorSnapshot): SignalFinding {
        val hits = snapshot.existingPaths.distinct().filter { it in KnownSignals.EMULATOR_PATHS || looksVirtualPath(it) }
        val critical = hits.any { it in KnownSignals.CRITICAL_EMULATOR_PATHS }
        val denied = snapshot.pathErrors.entries.joinToString("；") { "${it.key}=${it.value}" }
        return finding(
            signalId = "emu.file.nodes",
            category = category,
            severity = if (critical) Severity.CRITICAL else Severity.HIGH,
            confidence = 0.97,
            detected = hits.isNotEmpty(),
            titleZh = "模拟器管道、套接字与驱动节点",
            summaryZh = if (hits.isNotEmpty()) "文件系统上存在模拟器或虚拟机专用节点。" else "未发现模拟器管道、套接字或厂商残留文件。",
            observedDataZh = if (hits.isEmpty()) {
                "已探测 ${snapshot.probedPaths.size} 条路径，均未确认存在。" +
                    (if (denied.isEmpty()) "" else "权限受限因此不能判断的路径：$denied。")
            } else {
                "实际存在的路径：${hits.joinToString("，")}。" +
                    (if (denied.isEmpty()) "" else "另有权限受限路径：$denied。")
            },
            expectedBaselineZh = "真实物理手机不应出现 QEMU 管道节点，且 ro.kernel.qemu 应为空或 0；也不应出现 /dev/qemu_pipe、/dev/goldfish_pipe、/dev/socket/qemud、/dev/vboxguest、/sys/qemu_trace。",
            recommendationZh = BLOCK_SENSITIVE_RECOMMENDATION_ZH,
            rawEvidence = mapOf(
                "existing" to hits.joinToString(","),
                "probedCount" to snapshot.probedPaths.size.toString(),
                "errors" to denied,
            ) + snapshot.nativeHints.filterKeys { it.startsWith("path.") },
            sourceAttribution = Attribution.EMULATOR,
        )
    }

    private fun packages(snapshot: EmulatorSnapshot): SignalFinding {
        val hits = snapshot.installedPackages.filter { pkg ->
            KnownSignals.EMULATOR_PACKAGES.any { known -> pkg == known || pkg.startsWith("$known.") }
        }.distinct()
        return finding(
            signalId = "emu.pkg.known",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.9,
            detected = hits.isNotEmpty(),
            titleZh = "已知模拟器配套应用包名",
            summaryZh = if (hits.isNotEmpty()) "系统里安装了模拟器商店、启动器或增强包。" else "未安装已知模拟器配套包。",
            observedDataZh = if (hits.isEmpty()) {
                "已按包名查询 ${KnownSignals.EMULATOR_PACKAGES.size} 个已知模拟器包，均未安装。"
            } else {
                "实际安装：${hits.joinToString("，")}。"
            },
            expectedBaselineZh = "真实物理手机不会预装 BlueStacks、夜神、逍遥、MuMu、雷电、Genymotion 等模拟器配套包。Android 11 起未声明包可见性时查询会失败，失败本身不算命中。",
            recommendationZh = "发现模拟器配套包，建议阻断敏感操作，并核对包可见性查询是否完整。",
            rawEvidence = mapOf("installed" to hits.joinToString(",")),
            sourceAttribution = Attribution.EMULATOR,
        )
    }

    private fun graphics(snapshot: EmulatorSnapshot): SignalFinding {
        val renderer = snapshot.glRenderer
        val vendor = snapshot.glVendor
        val egl = snapshot.nativeProperties.getTrimmed("ro.hardware.egl")
        val blob = "$renderer $vendor $egl".lowercase()
        val markers = KnownSignals.GL_RENDERER_MARKERS.filter { it in blob }
        val eglHit = egl.lowercase() in setOf("emulation", "swiftshader", "angle") || "swiftshader" in egl.lowercase()
        val hit = markers.isNotEmpty() || eglHit
        val observed = if (renderer.isBlank() && vendor.isBlank()) {
            "未能读取 OpenGL 渲染器字符串。${snapshot.glError.ifBlank { "可能尚未建立 EGL（本地图形接口）上下文。" }} ro.hardware.egl=${show(egl)}。"
        } else {
            "实际读取：GL_RENDERER=${show(renderer)}，GL_VENDOR=${show(vendor)}，ro.hardware.egl=${show(egl)}。" +
                (if (markers.isEmpty()) "" else "命中特征：${markers.joinToString("、")}。")
        }
        return finding(
            signalId = "emu.gl.renderer",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.9,
            detected = hit,
            titleZh = "虚拟 GPU 与 OpenGL 渲染器",
            summaryZh = if (hit) "图形渲染器字符串指向软件渲染或模拟器 GPU。" else "图形渲染器未指向已知虚拟 GPU。",
            observedDataZh = observed,
            expectedBaselineZh = "真实物理手机的 GL_RENDERER 通常是 Adreno、Mali、PowerVR、Immortalis 等具体 GPU 型号，不应出现 SwiftShader、llvmpipe、virgl、Android Emulator、BlueStacks。",
            recommendationZh = BLOCK_SENSITIVE_RECOMMENDATION_ZH,
            rawEvidence = mapOf(
                "GL_RENDERER" to renderer,
                "GL_VENDOR" to vendor,
                "ro.hardware.egl" to egl,
                "glError" to snapshot.glError,
            ),
            sourceAttribution = Attribution.EMULATOR,
        )
    }

    private fun hypervisor(snapshot: EmulatorSnapshot): SignalFinding {
        val hit = ProcText.cpuinfoHasHypervisor(snapshot.cpuInfo)
        val processors = ProcText.cpuinfoProcessorCount(snapshot.cpuInfo)
        return finding(
            signalId = "emu.cpu.hypervisor",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.88,
            detected = hit,
            titleZh = "CPU 信息中的虚拟化痕迹",
            summaryZh = if (hit) "/proc/cpuinfo 出现 hypervisor、QEMU 或 goldfish 痕迹。" else "/proc/cpuinfo 未出现虚拟化痕迹。",
            observedDataZh = "解析到 processor 行 $processors 条。虚拟化关键词命中=$hit。原文摘录：${excerpt(snapshot.cpuInfo)}",
            expectedBaselineZh = "真实物理手机的 /proc/cpuinfo 描述具体 ARM CPU 实现者与型号，不应包含 hypervisor、QEMU、goldfish 字样。",
            recommendationZh = "CPU 信息与虚拟化监控器一致，建议阻断敏感操作，并与 ABI、核数核对结果一起看。",
            rawEvidence = mapOf(
                "processorCount" to processors.toString(),
                "hypervisor" to hit.toString(),
                "nativeHint" to snapshot.nativeHints.getOrDefault("cpu.hypervisor", ""),
            ),
            sourceAttribution = Attribution.EMULATOR,
        )
    }

    private fun translation(snapshot: EmulatorSnapshot): SignalFinding {
        val bridge = snapshot.nativeProperties.getTrimmed("ro.dalvik.vm.native.bridge")
        val enabled = snapshot.nativeProperties.getTrimmed("ro.enable.native.bridge.exec")
        val maps = snapshot.mapsText.lowercase()
        val libs = KnownSignals.TRANSLATION_LIBRARIES.filter { maps.contains(it.substringBefore(".so")) || bridge.lowercase().contains(it.substringBefore(".so")) }
        val hit = libs.isNotEmpty() || enabled == "1" || bridge.contains("houdini", ignoreCase = true) ||
            bridge.contains("ndk_translation", ignoreCase = true)
        return finding(
            signalId = "emu.cpu.translation",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.9,
            detected = hit,
            titleZh = "ARM 转译层（Houdini / ndk_translation）",
            summaryZh = if (hit) "进程映射或原生桥接属性显示当前进程在被转译执行。" else "未发现 ARM 转译层。",
            observedDataZh = "ro.dalvik.vm.native.bridge=${show(bridge)}，ro.enable.native.bridge.exec=${show(enabled)}。" +
                (if (libs.isEmpty()) "maps 中未发现 houdini 或 ndk_translation。" else "maps 或桥接名命中：${libs.joinToString("、")}。"),
            expectedBaselineZh = "真实 ARM 手机直接运行应用，不需要 libhoudini.so 或 libndk_translation.so，原生桥接属性应为空。x86 模拟器靠转译层运行 ARM 应用，这是强虚拟化信号。",
            recommendationZh = BLOCK_SENSITIVE_RECOMMENDATION_ZH,
            rawEvidence = mapOf(
                "ro.dalvik.vm.native.bridge" to bridge,
                "ro.enable.native.bridge.exec" to enabled,
                "libs" to libs.joinToString(","),
            ),
            sourceAttribution = Attribution.EMULATOR,
        )
    }

    private fun sensors(snapshot: EmulatorSnapshot): SignalFinding {
        val hits = snapshot.sensorNames.filter { name ->
            val lower = name.lowercase()
            KnownSignals.SENSOR_MARKERS.any { it in lower }
        }
        return finding(
            signalId = "emu.sensor.name",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.92,
            detected = hits.isNotEmpty(),
            titleZh = "虚拟传感器名称",
            summaryZh = if (hits.isNotEmpty()) "传感器名称带有 Goldfish、Ranchu 或 emulator 字样。" else "传感器名称未暴露虚拟器件。",
            observedDataZh = if (snapshot.sensorNames.isEmpty()) {
                "未枚举到传感器。空列表本身在本项不算命中，硬件一致性维度会再检查传感器是否齐全。"
            } else if (hits.isEmpty()) {
                "实际传感器：${snapshot.sensorNames.joinToString("，")}。"
            } else {
                "命中虚拟传感器名称：${hits.joinToString("，")}。全部名称：${snapshot.sensorNames.joinToString("，")}。"
            },
            expectedBaselineZh = "真实物理手机的加速度计、陀螺仪名称来自具体器件厂商（例如 LSM6DSO、BMI、ICM），不应叫 Goldfish 3-axis Accelerometer 或 Ranchu。",
            recommendationZh = BLOCK_SENSITIVE_RECOMMENDATION_ZH,
            rawEvidence = mapOf("sensors" to snapshot.sensorNames.joinToString(" | ")),
            sourceAttribution = Attribution.EMULATOR,
        )
    }

    private fun accelerometer(snapshot: EmulatorSnapshot): SignalFinding {
        val samples = snapshot.accelerometerSamples
        val stats = accelStats(samples)
        val constant = samples.size >= 5 && samples.distinct().size == 1
        val noGravity = stats != null && stats.meanMagnitude < 2.0
        val zeroNoise = stats != null && samples.size >= 5 && stats.magnitudeStddev < 0.002
        val hit = constant || noGravity || zeroNoise
        val severity = when {
            noGravity || constant -> Severity.HIGH
            else -> Severity.MEDIUM
        }
        val observed = if (samples.isEmpty()) {
            "本次没有采到加速度样本，不能判断噪声。未采样不算命中。"
        } else {
            "样本 ${samples.size} 个，不同取值 ${samples.distinct().size} 个，" +
                "合力均值=${stats?.meanMagnitude?.let { format(it) } ?: "-"}，" +
                "合力标准差=${stats?.magnitudeStddev?.let { format(it) } ?: "-"}。" +
                "首个样本=(${samples.first().x}, ${samples.first().y}, ${samples.first().z})。"
        }
        return finding(
            signalId = "emu.sensor.accel",
            category = category,
            severity = severity,
            confidence = 0.84,
            detected = hit,
            titleZh = "加速度计零噪声或恒定值",
            summaryZh = if (hit) "加速度序列没有真实器件应有的重力或噪声。" else "加速度序列具备变化，未呈现静态伪造。",
            observedDataZh = observed,
            expectedBaselineZh = "静止的真实手机仍应测到约 9.8 米/秒² 的重力，并且样本之间存在微小抖动。长时间完全相同、合力接近 0，或标准差接近 0，更像模拟器写死的传感器。",
            recommendationZh = "加速度被判定为静态伪造，建议阻断依赖体感或环境真实性的操作，并与传感器名称一起复核。",
            rawEvidence = mapOf(
                "sampleCount" to samples.size.toString(),
                "distinct" to samples.distinct().size.toString(),
                "meanMagnitude" to (stats?.meanMagnitude?.toString() ?: ""),
                "stddev" to (stats?.magnitudeStddev?.toString() ?: ""),
            ),
            sourceAttribution = Attribution.EMULATOR,
        )
    }

    private fun battery(snapshot: EmulatorSnapshot): SignalFinding {
        val temp = snapshot.batteryTemperatureTenthsC
        val voltage = snapshot.batteryVoltageMv
        val hit = temp == 0 && voltage == 0
        return finding(
            signalId = "emu.battery.static",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.8,
            detected = hit,
            titleZh = "零温零压的伪造电池",
            summaryZh = if (hit) "电池温度和电压同时为 0，符合模拟器静态伪造电池。" else "电池读数不是零温零压。",
            observedDataZh = "BatteryManager 温度（0.1℃）=${temp?.toString() ?: "未读到"}，电压（毫伏）=${voltage?.toString() ?: "未读到"}。",
            expectedBaselineZh = "真实物理手机的电池温度通常在 150 到 450（即 15℃ 到 45℃）量级，电压通常在 3000 到 4500 毫伏。两者同时精确为 0 是常见模拟器特征，不是正常放电。",
            recommendationZh = "电池读数不可信，建议与 /sys/class/power_supply 的跨层结果对照，并对敏感操作做二次校验。",
            rawEvidence = mapOf(
                "temperatureTenthsC" to (temp?.toString() ?: ""),
                "voltageMv" to (voltage?.toString() ?: ""),
            ),
            sourceAttribution = Attribution.EMULATOR,
        )
    }

    private fun cloudNic(snapshot: EmulatorSnapshot): SignalFinding {
        val names = snapshot.networkInterfaceNames.map { it.lowercase() }
        val hasEth = names.any { it == "eth0" || it.startsWith("eth") }
        val hasWifi = names.any { it.contains("wlan") || it.contains("wifi") }
        val hasCellular = names.any { it.contains("rmnet") || it.contains("ccmni") || it.contains("pdp") }
        val hit = names.isNotEmpty() && hasEth && !hasWifi && !hasCellular
        val identityBlob = (snapshot.javaBuild.values + snapshot.nativeProperties.values).joinToString(" ").lowercase()
        val cloudWord = KnownSignals.CLOUD_MARKERS.any { it in identityBlob }
        return finding(
            signalId = "emu.net.cloud",
            category = category,
            severity = if (cloudWord) Severity.HIGH else Severity.MEDIUM,
            confidence = if (cloudWord) 0.86 else 0.62,
            detected = hit,
            titleZh = "仅有线网卡的云手机形态",
            summaryZh = if (hit) "网卡只有以太网、没有无线网和蜂窝网，形态更像云手机或虚拟机。" else "网卡组合未呈现「只有有线网」的云手机形态。",
            observedDataZh = if (names.isEmpty()) {
                "未枚举到网卡，本项不命中。"
            } else {
                "实际网卡：${snapshot.networkInterfaceNames.joinToString("，")}。以太网=$hasEth，无线=$hasWifi，蜂窝=$hasCellular。"
            },
            expectedBaselineZh = "常见真实手机至少有 wlan 或蜂窝网卡（rmnet 等）。只有 eth0、没有 wlan/rmnet，多见于云手机和虚拟机。扩展坞有线网会额外增加网卡，但通常不会拿掉无线网。",
            recommendationZh = "网卡形态像云手机。单项不足以阻断，建议与 QEMU 属性、电池和渲染器一起判断，命中多项后再限制敏感操作。",
            rawEvidence = mapOf("interfaces" to snapshot.networkInterfaceNames.joinToString(",")),
            sourceAttribution = Attribution.EMULATOR,
        )
    }

    private fun affirmative(value: String): Boolean {
        if (value.isEmpty() || value == "0" || value.equals("false", ignoreCase = true)) return false
        return true
    }

    private fun looksVirtualPath(path: String): Boolean {
        val lower = path.lowercase()
        return "qemu" in lower || "goldfish" in lower || "vbox" in lower || "nox" in lower || "genyd" in lower
    }

    private fun firstNonBlank(vararg values: String): String = values.firstOrNull { it.isNotBlank() }.orEmpty()

    private fun show(value: String): String = if (value.isEmpty()) "（空）" else value

    private fun excerpt(text: String): String {
        val oneLine = text.replace('\n', ' ').trim()
        if (oneLine.isEmpty()) return "（空）"
        return if (oneLine.length <= 180) oneLine else oneLine.take(180) + "…"
    }

    private fun format(value: Double): String = ((value * 1000).toInt() / 1000.0).toString()

    private data class AccelStats(val meanMagnitude: Double, val magnitudeStddev: Double)

    private fun accelStats(samples: List<AccelSample>): AccelStats? {
        if (samples.isEmpty()) return null
        val magnitudes = samples.map { sample ->
            val value = sample.x * sample.x + sample.y * sample.y + sample.z * sample.z
            sqrt(value.toDouble())
        }
        val mean = magnitudes.average()
        val variance = magnitudes.sumOf { (it - mean) * (it - mean) } / magnitudes.size
        return AccelStats(mean, sqrt(variance))
    }
}
