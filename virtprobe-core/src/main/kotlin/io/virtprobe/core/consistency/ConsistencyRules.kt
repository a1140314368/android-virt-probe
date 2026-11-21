// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.core.consistency

import io.virtprobe.core.catalog.Attribution
import io.virtprobe.core.model.AccelSample
import io.virtprobe.core.model.BatteryReading
import io.virtprobe.core.model.ConsistencySnapshot
import io.virtprobe.core.model.KeystoreSnapshot
import io.virtprobe.core.model.Severity
import io.virtprobe.core.model.SignalCategory
import io.virtprobe.core.model.SignalFinding
import io.virtprobe.core.model.finding
import io.virtprobe.core.model.getTrimmed
import io.virtprobe.core.parse.ProcText
import kotlin.math.abs
import kotlin.math.sqrt

/**
 * Java Build、原生系统属性、proc/sys 与 Keystore 硬件背书的交叉校验。
 * 不一致通常说明改机、Java Hook，或两层采集里有一层被篡改。
 */
object ConsistencyRules {
    private val category = SignalCategory.CONSISTENCY

    private val buildPairs = listOf(
        "BRAND" to "ro.product.brand",
        "MANUFACTURER" to "ro.product.manufacturer",
        "MODEL" to "ro.product.model",
        "DEVICE" to "ro.product.device",
        "PRODUCT" to "ro.product.name",
        "HARDWARE" to "ro.hardware",
        "FINGERPRINT" to "ro.build.fingerprint",
        "BOARD" to "ro.product.board",
    )

    private val fingerprintKeys = listOf(
        "ro.build.fingerprint",
        "ro.system.build.fingerprint",
        "ro.vendor.build.fingerprint",
        "ro.odm.build.fingerprint",
        "ro.bootimage.build.fingerprint",
    )

    fun evaluate(snapshot: ConsistencySnapshot): List<SignalFinding> = listOf(
        javaVersusNative(snapshot),
        procVersusNative(snapshot),
        fingerprintFormat(snapshot),
        fingerprintPartitions(snapshot),
        identityChain(snapshot),
        bootState(snapshot),
        cpuCount(snapshot),
        abiKernel(snapshot),
        sensorSet(snapshot),
        sensorNoise(snapshot),
        batteryCross(snapshot),
        keystore(snapshot),
    )

    private fun javaVersusNative(snapshot: ConsistencySnapshot): SignalFinding {
        val mismatches = mutableListOf<String>()
        for ((javaKey, propKey) in buildPairs) {
            val javaValue = snapshot.javaBuild.getTrimmed(javaKey)
            val nativeValue = snapshot.nativeProperties.getTrimmed(propKey)
            if (javaValue.isEmpty() || nativeValue.isEmpty()) continue
            if (!javaValue.equals(nativeValue, ignoreCase = true)) {
                mismatches += "$javaKey=$javaValue 与 $propKey=$nativeValue"
            }
        }
        return finding(
            signalId = "con.cross.build",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.9,
            detected = mismatches.isNotEmpty(),
            titleZh = "Java Build 与原生属性不一致",
            summaryZh = if (mismatches.isNotEmpty()) "Build.* 和 __system_property_get 读到的身份字段不一致。" else "Java Build 与原生属性在可比字段上一致。",
            observedDataZh = if (mismatches.isEmpty()) {
                "已对照 ${buildPairs.size} 组字段，两边都有值的字段没有冲突。一边为空时不判断，避免把读失败当成改机。"
            } else {
                "冲突字段：${mismatches.joinToString("；")}。"
            },
            expectedBaselineZh = "真实手机上 Build.BRAND、MODEL、FINGERPRINT 等来自同一套系统属性。Java 层被 Hook 或改机工具只改了 Build 类时，两边会分裂。",
            recommendationZh = "跨层身份不一致，建议阻断敏感操作或触发二次实人校验，并保留两层原始值。",
            rawEvidence = mismatches.mapIndexed { index, value -> "mismatch$index" to value }.toMap(),
            sourceAttribution = Attribution.CONSISTENCY,
        )
    }

    private fun procVersusNative(snapshot: ConsistencySnapshot): SignalFinding {
        val javaText = normalizeProc(snapshot.javaProcCpuInfo)
        val nativeText = normalizeProc(snapshot.nativeProcCpuInfo)
        val comparable = javaText.isNotEmpty() && nativeText.isNotEmpty()
        val mismatch = comparable && javaText != nativeText
        return finding(
            signalId = "con.cross.cpuinfo",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.86,
            detected = mismatch,
            titleZh = "Java 与原生读取的 cpuinfo 不一致",
            summaryZh = if (mismatch) "两层读到的 /proc/cpuinfo 文本不一致，可能有一层被钩住。" else "两层 cpuinfo 一致，或其中一层没有读到。",
            observedDataZh = "Java 摘录长度=${snapshot.javaProcCpuInfo.length}，原生摘录长度=${snapshot.nativeProcCpuInfo.length}。" +
                "读取错误=${snapshot.readErrors["cpuinfo"] ?: "无"}。",
            expectedBaselineZh = "同一进程用 Java 文件流和原生 openat 读取 /proc/cpuinfo，内容应一致。只有一层被 Hook 时，两份文本会不同。任一端读失败都不算冲突。",
            recommendationZh = "proc 读取结果跨层不一致，建议按篡改处理敏感操作，并留存两份原文摘要。",
            rawEvidence = mapOf(
                "javaLength" to snapshot.javaProcCpuInfo.length.toString(),
                "nativeLength" to snapshot.nativeProcCpuInfo.length.toString(),
            ),
            sourceAttribution = Attribution.CONSISTENCY,
        )
    }

    private fun fingerprintFormat(snapshot: ConsistencySnapshot): SignalFinding {
        val fingerprint = firstNonBlank(
            snapshot.nativeProperties.getTrimmed("ro.build.fingerprint"),
            snapshot.javaBuild.getTrimmed("FINGERPRINT"),
        )
        val ok = fingerprint.isNotEmpty() && ProcText.isPlausibleFingerprint(fingerprint)
        val hit = fingerprint.isEmpty() || !ok
        return finding(
            signalId = "con.fingerprint.format",
            category = category,
            severity = if (fingerprint.isEmpty()) Severity.HIGH else Severity.MEDIUM,
            confidence = 0.8,
            detected = hit,
            titleZh = "构建指纹格式",
            summaryZh = if (hit) "ro.build.fingerprint 缺失或不符合标准分段格式。" else "构建指纹格式符合标准分段。",
            observedDataZh = "实际指纹=${fingerprint.ifBlank { "（空）" }}。",
            expectedBaselineZh = "标准格式是 brand/product/device:version/id/incremental:type/tags，例如 google/shiba/shiba:14/UQ1A.240205.002/11224170:user/release-keys。缺段、空格或随意拼接常见于改机。",
            recommendationZh = "指纹格式不合法。建议要求二次校验，并继续核对各分区指纹是否同源。",
            rawEvidence = mapOf("fingerprint" to fingerprint),
            sourceAttribution = Attribution.CONSISTENCY,
        )
    }

    private fun fingerprintPartitions(snapshot: ConsistencySnapshot): SignalFinding {
        val present = fingerprintKeys.mapNotNull { key ->
            val value = snapshot.nativeProperties.getTrimmed(key)
            if (value.isEmpty()) null else key to value
        }
        val identities = present.mapNotNull { (key, value) ->
            ProcText.fingerprintIdentity(value)?.let { key to it }
        }
        val distinct = identities.map { it.second }.distinct()
        val hit = distinct.size >= 2
        return finding(
            signalId = "con.fingerprint.partitions",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.88,
            detected = hit,
            titleZh = "多分区指纹不一致",
            summaryZh = if (hit) "system、vendor、odm 或 bootimage 指纹的品牌/产品/设备不一致。" else "已读到的分区指纹身份一致，或只读到一份。",
            observedDataZh = if (present.isEmpty()) {
                "没有读到分区指纹。"
            } else {
                present.joinToString("；") { (key, value) -> "$key=$value" } + "。"
            },
            expectedBaselineZh = "真实手机各分区指纹的 brand/product/device 三段应一致，增量版本号可以不同。把 system 伪装成一个品牌、vendor 仍是另一个品牌，是典型改机拼接。",
            recommendationZh = "分区指纹互相矛盾，建议阻断敏感操作，并把五份指纹原文提交风控。",
            rawEvidence = present.toMap(),
            sourceAttribution = Attribution.CONSISTENCY,
        )
    }

    private fun identityChain(snapshot: ConsistencySnapshot): SignalFinding {
        val brand = firstNonBlank(snapshot.javaBuild.getTrimmed("BRAND"), snapshot.nativeProperties.getTrimmed("ro.product.brand"))
        val manufacturer = firstNonBlank(
            snapshot.javaBuild.getTrimmed("MANUFACTURER"),
            snapshot.nativeProperties.getTrimmed("ro.product.manufacturer"),
        )
        val model = firstNonBlank(snapshot.javaBuild.getTrimmed("MODEL"), snapshot.nativeProperties.getTrimmed("ro.product.model"))
        val device = firstNonBlank(snapshot.javaBuild.getTrimmed("DEVICE"), snapshot.nativeProperties.getTrimmed("ro.product.device"))
        val hardware = firstNonBlank(snapshot.javaBuild.getTrimmed("HARDWARE"), snapshot.nativeProperties.getTrimmed("ro.hardware"))
        val blanks = listOf("brand" to brand, "manufacturer" to manufacturer, "model" to model, "device" to device, "hardware" to hardware)
            .filter { it.second.isBlank() }
            .map { it.first }
        val knownRealBrand = brand.lowercase() in REAL_BRANDS || manufacturer.lowercase() in REAL_BRANDS
        val virtualHardware = hardware.lowercase() in setOf("goldfish", "ranchu", "vbox86", "vbox86p", "cutf_cvm", "crosvm")
        val conflict = knownRealBrand && virtualHardware
        val hit = blanks.isNotEmpty() || conflict
        val severity = if (conflict) Severity.CRITICAL else Severity.MEDIUM
        return finding(
            signalId = "con.identity.chain",
            category = category,
            severity = severity,
            confidence = if (conflict) 0.94 else 0.7,
            detected = hit,
            titleZh = "品牌、厂商、型号与硬件链",
            summaryZh = when {
                conflict -> "品牌像真实厂商，但 hardware 仍是虚拟平台。"
                blanks.isNotEmpty() -> "身份链存在空字段。"
                else -> "品牌、厂商、型号、设备和硬件字段都有值，且没有明显冲突。"
            },
            observedDataZh = "brand=$brand，manufacturer=$manufacturer，model=$model，device=$device，hardware=$hardware。" +
                (if (blanks.isEmpty()) "" else "空字段：${blanks.joinToString("、")}。"),
            expectedBaselineZh = "真实手机这五项都不应为空，而且 hardware 应与品牌匹配。挂着商业品牌名字、hardware 却是 goldfish/ranchu/crosvm，说明身份被改过或仍在虚拟机里。",
            recommendationZh = if (conflict) {
                "身份链冲突，建议阻断敏感操作或触发二次实人校验。"
            } else {
                "身份字段不完整。建议与原生属性对照，空字段可能是采集失败，也可能是改机擦除。"
            },
            rawEvidence = mapOf(
                "brand" to brand,
                "manufacturer" to manufacturer,
                "model" to model,
                "device" to device,
                "hardware" to hardware,
            ),
            sourceAttribution = Attribution.CONSISTENCY,
        )
    }

    private fun bootState(snapshot: ConsistencySnapshot): SignalFinding {
        val verified = snapshot.nativeProperties.getTrimmed("ro.boot.verifiedbootstate").lowercase()
        val locked = snapshot.nativeProperties.getTrimmed("ro.boot.flash.locked")
        val vbmeta = snapshot.nativeProperties.getTrimmed("ro.boot.vbmeta.device_state").lowercase()
        val allEmpty = verified.isEmpty() && locked.isEmpty() && vbmeta.isEmpty()
        val badVerified = verified.isNotEmpty() && verified != "green"
        val unlocked = locked == "0" || vbmeta == "unlocked"
        val hit = badVerified || unlocked
        val severity = when (verified) {
            "red" -> Severity.HIGH
            else -> Severity.MEDIUM
        }
        return finding(
            signalId = "con.boot.state",
            category = category,
            severity = severity,
            confidence = 0.82,
            detected = hit,
            titleZh = "验证启动与锁状态",
            summaryZh = when {
                verified == "red" -> "验证启动状态为 red"
                verified == "yellow" -> "疑似自定义信任根，设备仍锁定"
                verified == "orange" || unlocked -> "疑似引导程序已解锁"
                allEmpty -> "没有读到启动校验属性"
                else -> "验证启动为 green，未发现解锁标记"
            },
            observedDataZh = "ro.boot.verifiedbootstate=${verified.ifBlank { "（空）" }}，ro.boot.flash.locked=${locked.ifBlank { "（空）" }}，ro.boot.vbmeta.device_state=${vbmeta.ifBlank { "（空）" }}。",
            expectedBaselineZh = "官方：green=锁定且官方信任根；yellow=锁定但自定义信任根；orange=已解锁。空值是未知。",
            recommendationZh = when {
                hit -> "解锁或自定义信任根不等于虚拟机。建议提高风控并对照 Keystore。"
                allEmpty -> "属性为空是未知，不要当成 green。"
                else -> "此项未形成异常结论。"
            },
            rawEvidence = mapOf(
                "verifiedbootstate" to verified,
                "flash.locked" to locked,
                "vbmeta.device_state" to vbmeta,
            ),
            sourceAttribution = Attribution.CONSISTENCY,
        )
    }

    private fun cpuCount(snapshot: ConsistencySnapshot): SignalFinding {
        val present = ProcText.cpuPresentCount(snapshot.sysCpuPresent)
        val cpuinfo = ProcText.cpuinfoProcessorCount(
            snapshot.nativeProcCpuInfo.ifBlank { snapshot.javaProcCpuInfo },
        ).takeIf { it > 0 }
        val runtime = snapshot.runtimeProcessors.takeIf { it > 0 }
        val problems = mutableListOf<String>()
        if (runtime != null && cpuinfo != null && runtime != cpuinfo) {
            problems += "Runtime.availableProcessors=$runtime 与 /proc/cpuinfo=$cpuinfo 不一致"
        }
        if (runtime != null && present != null && present < runtime) {
            problems += "/sys cpu present=$present 小于运行时可见核数 $runtime"
        }
        return finding(
            signalId = "con.cpu.count",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.84,
            detected = problems.isNotEmpty(),
            titleZh = "CPU 核数三方核对",
            summaryZh = if (problems.isNotEmpty()) "运行时、present 与 cpuinfo 的核数对不上。" else "可读到的核数来源没有互相矛盾。",
            observedDataZh = "Runtime.availableProcessors=${snapshot.runtimeProcessors}，/sys/devices/system/cpu/present=${snapshot.sysCpuPresent.ifBlank { "（空）" }}（解析=${present ?: "失败"}），/proc/cpuinfo processor 行=${cpuinfo ?: "无"}。",
            expectedBaselineZh = "在线核数应与 /proc/cpuinfo 的 processor 行数一致。present 可以大于在线核数（有核被离线），但不应小于运行时可见核数。三份数字被改成互相矛盾，常见于改机或虚拟机伪装核数。",
            recommendationZh = "核数跨层矛盾，建议与 uname 架构、转译层结果一起拦截或二次校验。",
            rawEvidence = mapOf(
                "runtime" to snapshot.runtimeProcessors.toString(),
                "present" to snapshot.sysCpuPresent,
                "cpuinfo" to (cpuinfo?.toString() ?: ""),
            ),
            sourceAttribution = Attribution.CONSISTENCY,
        )
    }

    private fun abiKernel(snapshot: ConsistencySnapshot): SignalFinding {
        val primary = snapshot.javaAbis.firstOrNull().orEmpty()
        val machine = snapshot.unameMachine
        val match = ProcText.abiMatchesKernel(machine, primary)
        val hit = machine.isNotBlank() && primary.isNotBlank() && !match
        return finding(
            signalId = "con.abi.uname",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.9,
            detected = hit,
            titleZh = "ABI 与内核架构",
            summaryZh = if (hit) "应用 ABI 与 uname 报告的内核架构不兼容。" else "ABI 与内核架构兼容，或其中一项缺失。",
            observedDataZh = "Java ABI 列表=${snapshot.javaAbis.joinToString("，").ifBlank { "（空）" }}，uname machine=${machine.ifBlank { "（空）" }}。",
            expectedBaselineZh = "arm64 内核可以跑 arm64 和 32 位 arm 应用，x86_64 内核同理。应用声称 arm64、内核却是 x86_64，说明正在转译或身份被改写。uname 读不到时不判断。",
            recommendationZh = "指令集与内核不一致，建议按模拟器转译或改机处理，并阻断依赖设备真实性的操作。",
            rawEvidence = mapOf(
                "abis" to snapshot.javaAbis.joinToString(","),
                "uname" to machine,
            ),
            sourceAttribution = Attribution.CONSISTENCY,
        )
    }

    private fun sensorSet(snapshot: ConsistencySnapshot): SignalFinding {
        val types = snapshot.sensors.map { it.type }.toSet()
        val missingAccel = snapshot.sensors.isNotEmpty() && SensorType.ACCELEROMETER !in types
        val empty = snapshot.sensors.isEmpty()
        val hit = empty || missingAccel
        return finding(
            signalId = "con.sensor.set",
            category = category,
            severity = Severity.MEDIUM,
            confidence = 0.68,
            detected = hit,
            titleZh = "物理传感器完备性",
            summaryZh = when {
                empty -> "没有枚举到任何传感器。"
                missingAccel -> "传感器列表里没有加速度计。"
                else -> "至少存在加速度计。"
            },
            observedDataZh = if (empty) {
                "SensorManager 返回空列表。"
            } else {
                "实际传感器：${snapshot.sensors.joinToString("，") { "${it.name}(type=${it.type}, vendor=${it.vendor})" }}。"
            },
            expectedBaselineZh = "手机形态的真机应有加速度计。电视盒子或特殊工控设备可能没有，所以本项只到中危。空列表在模拟器上很常见，也可能是采集时机问题。",
            recommendationZh = "传感器集合不像普通手机。请与传感器名称、加速度噪声一起看，不要只凭缺传感器阻断平板或电视。",
            rawEvidence = mapOf("count" to snapshot.sensors.size.toString()),
            sourceAttribution = Attribution.CONSISTENCY,
        )
    }

    private fun sensorNoise(snapshot: ConsistencySnapshot): SignalFinding {
        val samples = snapshot.accelerometerSamples
        val stats = magnitudeStats(samples)
        val zeroNoise = stats != null && samples.size >= 6 && stats.stddev < 0.002
        val noGravity = stats != null && samples.size >= 6 && stats.mean < 2.0
        val hit = zeroNoise || noGravity
        return finding(
            signalId = "con.sensor.noise",
            category = category,
            severity = if (noGravity) Severity.HIGH else Severity.MEDIUM,
            confidence = 0.8,
            detected = hit,
            titleZh = "加速度动态噪声",
            summaryZh = if (hit) "加速度序列缺少真机应有的重力或动态噪声。" else "加速度噪声未被判定为静态伪造，或样本不足。",
            observedDataZh = if (stats == null) {
                "样本 ${samples.size} 个，不足 6 个时不判断噪声。"
            } else {
                "样本 ${samples.size} 个，合力均值=${format(stats.mean)}，标准差=${format(stats.stddev)}。"
            },
            expectedBaselineZh = "静止真机的合力应接近 9.8 米/秒²，且连续样本不会精确相同。标准差长期低于 0.002 或合力接近 0，说明数值是写死的。",
            recommendationZh = "传感器动态特征不像物理器件，建议与模拟器传感器名称合并判断后再限制敏感操作。",
            rawEvidence = mapOf(
                "count" to samples.size.toString(),
                "mean" to (stats?.mean?.toString() ?: ""),
                "stddev" to (stats?.stddev?.toString() ?: ""),
            ),
            sourceAttribution = Attribution.CONSISTENCY,
        )
    }

    private fun batteryCross(snapshot: ConsistencySnapshot): SignalFinding {
        val java = snapshot.javaBattery
        val sys = snapshot.sysBattery
        val problems = mutableListOf<String>()
        val tempJava = java?.temperatureTenthsC
        val tempSys = sys?.temperatureTenthsC
        if (tempJava != null && tempSys != null && abs(tempJava - tempSys) >= 80) {
            problems += "温度 Java=$tempJava 与 sysfs=$tempSys（0.1℃）相差超过 8℃"
        }
        val voltJava = java?.voltageMv
        val voltSys = sys?.voltageMv
        if (voltJava != null && voltSys != null && voltJava > 0 && voltSys > 0) {
            val diff = abs(voltJava - voltSys).toDouble() / maxOf(voltJava, voltSys)
            if (diff > 0.15) problems += "电压 Java=${voltJava}mV 与 sysfs=${voltSys}mV 相对差超过 15%"
        }
        if (tempJava == 0 && voltJava == 0 && tempSys != null && tempSys > 0) {
            problems += "Java 电池为 0，sysfs 温度却是 $tempSys"
        }
        return finding(
            signalId = "con.battery.cross",
            category = category,
            severity = Severity.MEDIUM,
            confidence = 0.76,
            detected = problems.isNotEmpty(),
            titleZh = "电池跨层读数",
            summaryZh = if (problems.isNotEmpty()) "Java 电池广播与 sysfs 电池节点不一致。" else "两层电池读数没有超出容差，或缺少可比数据。",
            observedDataZh = "Java 温度=${tempJava ?: "无"}、电压=${voltJava ?: "无"}、电量=${java?.capacityPercent ?: "无"}；" +
                "sysfs 温度=${tempSys ?: "无"}、电压=${voltSys ?: "无"}、电量=${sys?.capacityPercent ?: "无"}。" +
                (if (problems.isEmpty()) "" else "差异：${problems.joinToString("；")}。"),
            expectedBaselineZh = "两层读的是同一块电池，温度差不应超过约 8℃，电压相对差不应超过 15%。Java 被改成 0 而 sysfs 仍有温度，说明上层读数被伪造。权限读不到 sysfs 时不判断。",
            recommendationZh = "电池跨层不一致，建议按伪造传感器处理，并与零温零压规则一起复核。",
            rawEvidence = mapOf("problems" to problems.joinToString(" | ")),
            sourceAttribution = Attribution.CONSISTENCY,
        )
    }

    private fun keystore(snapshot: ConsistencySnapshot): SignalFinding {
        val ks = snapshot.keystore
        if (ks == null || !ks.available) {
            return finding(
                signalId = "con.keystore.tee",
                category = category,
                severity = Severity.INFO,
                confidence = 0.0,
                detected = false,
                titleZh = "Keystore / TEE 硬件背书",
                summaryZh = "本次没有可用的 Android Keystore 证明结果。",
                observedDataZh = "Keystore 不可用。原因=${ks?.error ?: "未采集"}。",
                expectedBaselineZh = "具备 TEE（可信执行环境）的真机可以生成硬件背书密钥，并在证明扩展里给出 RootOfTrust（可信根，含启动验证状态和是否锁定）。模拟器经常只能生成软件密钥，或根本生成失败。生成失败本身可能是系统限制，不能直接当成命中。",
                recommendationZh = "未能完成硬件背书，不要把采集失败单独当成虚拟机证据。",
                rawEvidence = mapOf("error" to (ks?.error ?: "not-collected")),
                sourceAttribution = Attribution.CONSISTENCY,
            )
        }
        val software = ks.insideSecureHardware == false || ks.attestationSecurityLevel.equals("Software", ignoreCase = true)
        val badBoot = ks.verifiedBootState.equals("Unverified", ignoreCase = true) ||
            ks.verifiedBootState.equals("Failed", ignoreCase = true)
        val selfSigned = ks.verifiedBootState.equals("SelfSigned", ignoreCase = true)
        val unlocked = ks.deviceLocked == false
        val missingAttestation = !ks.attestationPresent && ks.insideSecureHardware == true
        val hit = software || badBoot || selfSigned || unlocked || missingAttestation
        val severity = when {
            software || badBoot -> Severity.HIGH
            else -> Severity.MEDIUM
        }
        return finding(
            signalId = "con.keystore.tee",
            category = category,
            severity = severity,
            confidence = 0.87,
            detected = hit,
            titleZh = "Keystore / TEE 硬件背书",
            summaryZh = if (hit) "密钥不在安全硬件中，或可信根显示启动链异常。" else "密钥位于安全硬件，且可信根没有报告失败或解锁。",
            observedDataZh = "insideSecureHardware=${ks.insideSecureHardware}，证明扩展=${ks.attestationPresent}，" +
                "安全级别=${ks.attestationSecurityLevel ?: "未知"}，verifiedBootState=${ks.verifiedBootState ?: "未解析"}，" +
                "deviceLocked=${ks.deviceLocked?.toString() ?: "未解析"}。错误=${ks.error ?: "无"}。",
            expectedBaselineZh = "真机的密钥应 isInsideSecureHardware=true，证明安全级别应为 TrustedEnvironment 或 StrongBox，RootOfTrust 的 verifiedBootState 应为 Verified，deviceLocked 应为 true。软件密钥或 Unverified/Failed 说明没有可靠的硬件背书。",
            recommendationZh = "缺少可信硬件背书或启动链异常，建议限制高风险交易，并与 ro.boot.verifiedbootstate 对照。",
            rawEvidence = mapOf(
                "insideSecureHardware" to ks.insideSecureHardware.toString(),
                "attestationPresent" to ks.attestationPresent.toString(),
                "securityLevel" to ks.attestationSecurityLevel.orEmpty(),
                "verifiedBootState" to ks.verifiedBootState.orEmpty(),
                "deviceLocked" to (ks.deviceLocked?.toString() ?: ""),
                "error" to ks.error.orEmpty(),
            ),
            sourceAttribution = Attribution.CONSISTENCY,
        )
    }

    private fun normalizeProc(text: String): String = text.replace("\r\n", "\n").trim()

    private fun firstNonBlank(vararg values: String): String = values.firstOrNull { it.isNotBlank() }.orEmpty()

    private data class Stats(val mean: Double, val stddev: Double)

    private fun magnitudeStats(samples: List<AccelSample>): Stats? {
        if (samples.isEmpty()) return null
        val values = samples.map { sample ->
            sqrt((sample.x * sample.x + sample.y * sample.y + sample.z * sample.z).toDouble())
        }
        val mean = values.average()
        val variance = values.sumOf { (it - mean) * (it - mean) } / values.size
        return Stats(mean, sqrt(variance))
    }

    private fun format(value: Double): String = ((value * 1000).toInt() / 1000.0).toString()

    private object SensorType {
        const val ACCELEROMETER: Int = 1
    }

    private val REAL_BRANDS = setOf(
        "google", "samsung", "xiaomi", "huawei", "oppo", "vivo", "oneplus", "honor",
        "realme", "meizu", "sony", "motorola", "nothing", "asus", "lenovo", "zte", "nubia",
    )
}
