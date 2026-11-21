// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.core.runtime

import io.virtprobe.core.model.ProbeVisibility
import io.virtprobe.core.model.RuntimeSnapshot
import io.virtprobe.core.model.Severity
import io.virtprobe.core.model.SignalCategory
import io.virtprobe.core.model.SignalFinding
import io.virtprobe.core.model.finding
import java.util.Calendar
import java.util.TimeZone

/**
 * 运行环境信号。用户可见的四段话都保持短句。
 * 原理、误报和出处放在 [sourceAttribution] 与 rawEvidence，不写进摘要。
 */
object RuntimeRules {
    private val category = SignalCategory.RUNTIME
    private const val SOURCE =
        "路径思路参考 scottyab/rootbeer（Apache-2.0，commit de7bc7b）。Magisk 为 GPL-3.0，只采用公开安装目录名，未复制其源码。调试看 TracerPid 与 Debug.isDebuggerConnected，依据 OWASP MASTG-KNOW-0028。Verified Boot 的 green/yellow/orange 依据 AOSP 启动流程文档。未复制 GPL 检测器源码。"

    fun parseTracerPid(status: String): Int? {
        val line = status.lineSequence().firstOrNull {
            it.trimStart().startsWith("TracerPid", ignoreCase = true)
        } ?: return null
        return line.substringAfter(':', "").trim().toIntOrNull()
    }

    /** 只匹配库名或路径片段，避免短词 lspd 碰到无关字符串。 */
    fun mapMarkers(text: String): List<String> {
        if (text.isBlank()) return emptyList()
        val lower = text.lowercase()
        val keys = listOf(
            "frida-agent",
            "frida-gadget",
            "libfrida",
            "zygisk",
            "libriru",
            "libxposed",
            "lspd.so",
            "/lspd",
        )
        return keys.filter { lower.contains(it) }
    }

    /**
     * Frida 17 的抽象套接字前缀。两次启动后缀不同，前缀稳定。
     * 不匹配裸词 frida，避免把无关套接字名当成注入。
     */
    fun unixMarkers(text: String): List<String> {
        if (text.isBlank()) return emptyList()
        return if (text.lowercase().contains("frida-zymbiote")) listOf("frida-zymbiote") else emptyList()
    }

    fun evaluate(snapshot: RuntimeSnapshot): List<SignalFinding> = listOf(
        suPaths(snapshot),
        mounts(snapshot),
        injectedMaps(snapshot),
        debugger(snapshot),
        selinux(snapshot),
        buildTrust(snapshot),
        patch(snapshot),
        posture(snapshot),
        packages(snapshot),
    )

    private fun suPaths(snapshot: RuntimeSnapshot): SignalFinding {
        val present = snapshot.binaryProbes.filterValues { it == ProbeVisibility.PRESENT }.keys.toList()
        val denied = snapshot.binaryProbes.filterValues { it == ProbeVisibility.DENIED }.keys.toList()
        val hit = present.isNotEmpty()
        val unknown = !hit && denied.isNotEmpty()
        return finding(
            signalId = "rt.su.paths",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.72,
            detected = hit,
            titleZh = "su / Magisk 路径",
            summaryZh = when {
                hit -> "疑似存在提权文件"
                unknown -> "无法检查"
                else -> "未看到这些路径"
            },
            observedDataZh = when {
                hit -> "存在：" + present.joinToString("、")
                unknown -> "拒绝读取：" + denied.joinToString("、")
                else -> "已查 ${snapshot.binaryProbes.size} 条，均不可见"
            },
            expectedBaselineZh = "量产机通常看不到 su、Magisk、KernelSU、APatch 目录。看不到不等于没有。",
            recommendationZh = if (hit) "线索，不等于恶意。建议复核 Root 管理器。" else "隐藏后会漏报，不能据此认为未提权。",
            rawEvidence = snapshot.binaryProbes.mapValues { it.value.name },
            sourceAttribution = SOURCE,
        )
    }

    private fun mounts(snapshot: RuntimeSnapshot): SignalFinding {
        val unknown = snapshot.mountState == ProbeVisibility.DENIED
        val hit = snapshot.mountHits.isNotEmpty()
        return finding(
            signalId = "rt.mount.markers",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.8,
            detected = hit,
            titleZh = "挂载中的提权痕迹",
            summaryZh = when {
                hit -> "疑似 Magisk/KSU/APatch 挂载"
                unknown -> "无法检查"
                else -> "未看到相关挂载"
            },
            observedDataZh = when {
                hit -> snapshot.mountHits.joinToString("、")
                unknown -> "mountinfo 被拒绝"
                else -> "mountinfo 可读，无 magisk/ksu/apatch 字样"
            },
            expectedBaselineZh = "量产挂载一般不含 magisk、zygisk、/data/adb/ksu、/data/adb/ap。",
            recommendationZh = if (hit) "系统级 Root 线索。不要单凭挂载字符串封禁。" else "读不到时结果未知。",
            rawEvidence = mapOf("state" to snapshot.mountState.name, "hits" to snapshot.mountHits.joinToString("|")),
            sourceAttribution = SOURCE,
        )
    }

    private fun injectedMaps(snapshot: RuntimeSnapshot): SignalFinding {
        val mapHit = snapshot.mapHits.isNotEmpty()
        val unixHit = snapshot.unixHits.isNotEmpty()
        val hit = mapHit || unixHit
        val mapsDenied = snapshot.mapsState == ProbeVisibility.DENIED
        val unixDenied = snapshot.unixState == ProbeVisibility.DENIED
        val unknown = !hit && (mapsDenied || unixDenied)
        return finding(
            signalId = "rt.maps.inject",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.7,
            detected = hit,
            titleZh = "进程内注入库",
            summaryZh = when {
                hit -> "疑似 Hook 或注入库"
                unknown -> "无法检查"
                else -> "未看到已知注入库"
            },
            observedDataZh = when {
                hit -> (snapshot.mapHits + snapshot.unixHits).joinToString("、")
                mapsDenied && unixDenied -> "maps 与套接字表都被拒绝"
                mapsDenied -> "maps 被拒绝"
                unixDenied -> "maps 可读，无库名。套接字表不可读"
                else -> "maps 与套接字表可读，无已知注入名"
            },
            expectedBaselineZh = "普通进程 maps 不含 frida-gadget、zygisk、libxposed。Frida 17 可能不留这些名字。",
            recommendationZh = if (hit) {
                "弱到中等线索，不等于识别了全部隐藏框架。"
            } else if (unknown) {
                "读不到的通道是未知，不要当成未发现注入。"
            } else {
                "未看到不等于没有注入。"
            },
            rawEvidence = mapOf(
                "maps" to snapshot.mapsState.name,
                "mapHits" to snapshot.mapHits.joinToString("|"),
                "unix" to snapshot.unixState.name,
                "unixHits" to snapshot.unixHits.joinToString("|"),
            ),
            sourceAttribution = SOURCE,
        )
    }

    private fun debugger(snapshot: RuntimeSnapshot): SignalFinding {
        val tracer = snapshot.tracerPid
        val java = snapshot.javaDebuggerConnected
        val unknown = tracer == null && java == null
        val hit = (tracer != null && tracer > 0) || java == true
        return finding(
            signalId = "rt.debug.tracer",
            category = category,
            severity = Severity.HIGH,
            confidence = 0.9,
            detected = hit,
            titleZh = "调试器",
            summaryZh = when {
                hit -> "疑似调试器已附加"
                unknown -> "无法检查"
                else -> "未发现调试器"
            },
            observedDataZh = "TracerPid=${tracer?.toString() ?: "无法读取"}，Java调试器=${java?.toString() ?: "无法读取"}",
            expectedBaselineZh = "TracerPid 为 0 且 Debug.isDebuggerConnected 为 false。只表示此刻没有调试器。",
            recommendationZh = if (hit) "调试线索。开发机上可能是本人在调试。" else "未附加不等于没有其他注入。",
            rawEvidence = mapOf("tracerPid" to (tracer?.toString() ?: ""), "javaDebugger" to (java?.toString() ?: "")),
            sourceAttribution = SOURCE,
        )
    }

    private fun selinux(snapshot: RuntimeSnapshot): SignalFinding {
        val value = snapshot.selinuxEnforce?.trim().orEmpty()
        val hit = value == "0"
        val unknown = value.isEmpty()
        return finding(
            signalId = "rt.selinux.mode",
            category = category,
            severity = Severity.MEDIUM,
            confidence = 0.75,
            detected = hit,
            titleZh = "SELinux",
            summaryZh = when {
                hit -> "线索：SELinux 为 Permissive"
                unknown -> "无法检查"
                value == "1" -> "SELinux 为 Enforcing"
                else -> "SELinux 值无法识别"
            },
            observedDataZh = if (unknown) "enforce 节点不可读" else "enforce=$value",
            expectedBaselineZh = "量产用户系统多为 Enforcing(1)。因设备策略而异。读不到是未知，不是正常。",
            recommendationZh = if (hit) "Permissive 降低隔离，不等于已被入侵。" else "无法读取时不要当成 Enforcing。",
            rawEvidence = mapOf("enforce" to value),
            sourceAttribution = SOURCE,
        )
    }

    private fun buildTrust(snapshot: RuntimeSnapshot): SignalFinding {
        val tags = snapshot.buildTags.trim()
        val secure = snapshot.roSecure.trim()
        val debuggable = snapshot.roDebuggable.trim()
        val unknown = tags.isEmpty() && secure.isEmpty() && debuggable.isEmpty()
        val testKeys = tags.contains("test-keys") || tags.contains("dev-keys")
        val insecure = secure == "0" || debuggable == "1"
        val hit = testKeys || insecure
        return finding(
            signalId = "rt.build.trust",
            category = category,
            severity = Severity.MEDIUM,
            confidence = 0.66,
            detected = hit,
            titleZh = "系统构建标记",
            summaryZh = when {
                hit -> "疑似测试或可调试系统"
                unknown -> "无法检查"
                else -> "构建标记像量产用户系统"
            },
            observedDataZh = "tags=${tags.ifBlank { "未读到" }}，ro.secure=${secure.ifBlank { "未读到" }}，ro.debuggable=${debuggable.ifBlank { "未读到" }}",
            expectedBaselineZh = "用户版常见 release-keys、ro.secure=1、ro.debuggable=0。模拟器和工程机会不同。",
            recommendationZh = if (hit) "说明系统不是常规用户版。不等于恶意。" else "属性被隐藏时会漏报。",
            rawEvidence = mapOf("tags" to tags, "ro.secure" to secure, "ro.debuggable" to debuggable),
            sourceAttribution = SOURCE,
        )
    }

    private fun patch(snapshot: RuntimeSnapshot): SignalFinding {
        val raw = snapshot.securityPatch.trim()
        val date = parseIsoDate(raw)
        val now = if (snapshot.nowEpochMs > 0) utcMonths(snapshot.nowEpochMs) else null
        val months = if (date != null && now != null) now - date else null
        val badFormat = raw.isNotEmpty() && date == null
        val old = months != null && months >= 24
        return finding(
            signalId = "rt.patch.date",
            category = category,
            severity = if (badFormat) Severity.LOW else Severity.INFO,
            confidence = 0.5,
            detected = badFormat,
            titleZh = "安全补丁日期",
            summaryZh = when {
                raw.isEmpty() -> "无法检查"
                badFormat -> "补丁日期格式异常"
                old -> "补丁较早，因厂商而异"
                else -> "补丁日期可读"
            },
            observedDataZh = if (raw.isEmpty()) "SECURITY_PATCH 为空" else "SECURITY_PATCH=$raw",
            expectedBaselineZh = "公开格式是 YYYY-MM-DD。没有统一的“必须新于某月”标准。",
            recommendationZh = if (badFormat) "格式不像官方补丁级别，建议复核。" else "日期旧只是线索，不单独当异常。",
            rawEvidence = mapOf("patch" to raw, "ageMonths" to (months?.toString() ?: "")),
            sourceAttribution = SOURCE,
        )
    }

    private fun posture(snapshot: RuntimeSnapshot): SignalFinding {
        val proxy = snapshot.httpProxy?.trim().orEmpty()
        val parts = listOf(
            "ADB=" + flag(snapshot.adbEnabled),
            "VPN=" + flag(snapshot.vpnActive),
            "代理=" + (proxy.ifBlank { "无" }),
        )
        return finding(
            signalId = "rt.net.posture",
            category = category,
            severity = Severity.INFO,
            confidence = 0.0,
            detected = false,
            titleZh = "ADB / VPN / 代理",
            summaryZh = "记录网络与调试开关，本身不等于异常",
            observedDataZh = parts.joinToString("，"),
            expectedBaselineZh = "因设备和使用策略而异。开着 VPN、代理或 ADB 不能当成被入侵。",
            recommendationZh = "只作环境说明。不要据此拦截。",
            rawEvidence = mapOf(
                "adb" to flag(snapshot.adbEnabled),
                "vpn" to flag(snapshot.vpnActive),
                "proxy" to proxy,
            ),
            sourceAttribution = SOURCE,
        )
    }

    private fun packages(snapshot: RuntimeSnapshot): SignalFinding {
        val hits = snapshot.cluePackages
        return finding(
            signalId = "rt.pkg.clue",
            category = category,
            severity = Severity.LOW,
            confidence = 0.4,
            detected = hits.isNotEmpty(),
            titleZh = "管理器包名",
            summaryZh = if (hits.isEmpty()) "未看到已知管理器包" else "线索：装有 Root/Hook 管理器",
            observedDataZh = if (hits.isEmpty()) "查询列表为空" else hits.joinToString("、"),
            expectedBaselineZh = "包名只是弱线索。未安装或被隐藏都不等于没有提权。",
            recommendationZh = if (hits.isEmpty()) "不要把查不到当成环境正常。" else "已安装不等于正在提权。",
            rawEvidence = mapOf("packages" to hits.joinToString(",")),
            sourceAttribution = SOURCE,
        )
    }

    private fun parseIsoDate(raw: String): Int? {
        val parts = raw.split('-')
        if (parts.size != 3) return null
        val year = parts[0].toIntOrNull() ?: return null
        val month = parts[1].toIntOrNull() ?: return null
        val day = parts[2].toIntOrNull() ?: return null
        if (year !in 2008..2100 || month !in 1..12 || day !in 1..31 || parts[0].length != 4) return null
        return year * 12 + (month - 1)
    }

    private fun utcMonths(epochMs: Long): Int {
        val calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
        calendar.timeInMillis = epochMs
        return calendar.get(Calendar.YEAR) * 12 + calendar.get(Calendar.MONTH)
    }

    private fun flag(value: Boolean?): String = when (value) {
        true -> "开"
        false -> "关"
        null -> "无法读取"
    }
}
