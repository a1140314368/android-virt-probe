// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.core.parse

/**
 * 不依赖 Android 的文本解析器。Kotlin 规则用它做最终判定；
 * 原生层有一套对齐的 C++ 解析器，用来在采集端先整理证据。判定权在本模块。
 */
object ProcText {
    private val mapLine = Regex("""^[0-9a-fA-F]+-[0-9a-fA-F]+\s+(\S+)\s+\S+\s+\S+\s+\d+\s*(.*)$""")
    private val fingerprint = Regex("""^([^/:\s]+)/([^/:\s]+)/([^/:\s]+):[^/:\s]+/[^/:\s]+/[^/:\s]+:[^/:\s]+/[^/:\s]+$""")

    /** 解析 `/sys/devices/system/cpu/present`，例如 `0-7` 或 `0-3,5`。无法解析时返回 null。 */
    fun cpuPresentCount(text: String): Int? {
        val trimmed = text.trim()
        if (trimmed.isEmpty()) return null
        var count = 0
        for (raw in trimmed.split(',')) {
            val part = raw.trim()
            if (part.isEmpty()) return null
            if ('-' in part) {
                val pieces = part.split('-')
                if (pieces.size != 2) return null
                val start = pieces[0].toIntOrNull() ?: return null
                val end = pieces[1].toIntOrNull() ?: return null
                if (end < start || start < 0) return null
                count += end - start + 1
            } else {
                if (part.toIntOrNull() == null) return null
                count += 1
            }
        }
        return count.takeIf { it > 0 }
    }

    /** `/proc/cpuinfo` 里 `processor : N` 的行数。 */
    fun cpuinfoProcessorCount(cpuinfo: String): Int {
        return cpuinfo.lineSequence().count { line ->
            val trimmed = line.trim()
            trimmed.startsWith("processor") && trimmed.contains(':')
        }
    }

    fun cpuinfoHasHypervisor(cpuinfo: String): Boolean {
        val lower = cpuinfo.lowercase()
        return "hypervisor" in lower || "qemu" in lower || "goldfish" in lower
    }

    /** 从 `/proc/self/maps` 抽出权限和路径。路径可能为空（匿名映射）。 */
    fun parseMaps(text: String): List<MapEntry> {
        val out = mutableListOf<MapEntry>()
        for (line in text.lineSequence()) {
            val match = mapLine.matchEntire(line.trim()) ?: continue
            out += MapEntry(perms = match.groupValues[1], path = match.groupValues[2].trim())
        }
        return out
    }

    /**
     * 解析 `/proc/self/mountinfo` 的挂载点和文件系统类型。
     * 挂载点里的八进制转义 `\040` 会还原成空格。
     */
    fun parseMountInfo(text: String): List<MountEntry> {
        val out = mutableListOf<MountEntry>()
        for (line in text.lineSequence()) {
            val separator = line.indexOf(" - ")
            if (separator < 0) continue
            val left = line.substring(0, separator)
            val right = line.substring(separator + 3).trim()
            val leftFields = left.split(' ')
            if (leftFields.size < 5) continue
            val rightFields = right.split(' ')
            if (rightFields.size < 2) continue
            out += MountEntry(
                mountPoint = unescape(leftFields[4]),
                fstype = rightFields[0],
                source = unescape(rightFields[1]),
            )
        }
        return out
    }

    /** 解析 environ 文本。Android 用 NUL 分隔，测试夹具里也允许换行。 */
    fun parseEnviron(text: String): Map<String, String> {
        if (text.isEmpty()) return emptyMap()
        val out = linkedMapOf<String, String>()
        for (part in text.split('\u0000', '\n')) {
            if (part.isEmpty()) continue
            val eq = part.indexOf('=')
            if (eq <= 0) continue
            out[part.substring(0, eq)] = part.substring(eq + 1)
        }
        return out
    }

    /** 解析 `/proc/bus/input/devices`。 */
    fun parseInputDevices(text: String): List<ProcInputDevice> {
        val devices = mutableListOf<ProcInputDevice>()
        var name = ""
        var vendor: Int? = null
        var product: Int? = null
        var bus = ""
        var handlers = ""
        fun flush() {
            if (name.isEmpty() && handlers.isEmpty() && vendor == null) return
            devices += ProcInputDevice(name = name, vendor = vendor, product = product, bus = bus, handlers = handlers)
            name = ""
            vendor = null
            product = null
            bus = ""
            handlers = ""
        }
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty()) {
                flush()
                continue
            }
            when {
                line.startsWith("N: Name=") -> {
                    name = line.substringAfter("Name=").trim().removeSurrounding("\"")
                }
                line.startsWith("I:") -> {
                    bus = token(line, "Bus=") ?: bus
                    vendor = token(line, "Vendor=")?.toIntOrNull(16)
                    product = token(line, "Product=")?.toIntOrNull(16)
                }
                line.startsWith("H: Handlers=") -> handlers = line.substringAfter("Handlers=").trim()
            }
        }
        flush()
        return devices
    }

    /** 指纹是否符合 `brand/product/device:release/id/incremental:type/tags`。 */
    fun isPlausibleFingerprint(value: String): Boolean = fingerprint.matches(value.trim())

    /** 取指纹前三段：品牌、产品名、设备名。格式不对时返回 null。 */
    fun fingerprintIdentity(value: String): FingerprintIdentity? {
        val match = fingerprint.matchEntire(value.trim()) ?: return null
        return FingerprintIdentity(
            brand = match.groupValues[1],
            product = match.groupValues[2],
            device = match.groupValues[3],
        )
    }

    fun abiFamily(abi: String): String = when (abi.lowercase()) {
        "arm64-v8a" -> "arm64"
        "armeabi-v7a", "armeabi" -> "arm"
        "x86_64" -> "x86_64"
        "x86" -> "x86"
        "riscv64" -> "riscv64"
        else -> abi.lowercase()
    }

    fun unameFamily(machine: String): String {
        val m = machine.lowercase()
        return when {
            m.contains("aarch64") || m == "arm64" -> "arm64"
            m.startsWith("arm") -> "arm"
            m.contains("x86_64") || m == "amd64" -> "x86_64"
            m.contains("i686") || m.contains("i386") || m == "x86" -> "x86"
            m.contains("riscv64") -> "riscv64"
            else -> "unknown"
        }
    }

    /** 32 位应用跑在 64 位内核上是正常的，不能算不一致。 */
    fun abiMatchesKernel(unameMachine: String, abi: String): Boolean {
        val kernel = unameFamily(unameMachine)
        val app = abiFamily(abi)
        if (kernel == "unknown" || abi.isBlank()) return true
        return when (kernel) {
            "arm64" -> app == "arm64" || app == "arm"
            "arm" -> app == "arm"
            "x86_64" -> app == "x86_64" || app == "x86"
            "x86" -> app == "x86"
            "riscv64" -> app == "riscv64"
            else -> true
        }
    }

    private fun token(line: String, key: String): String? {
        val start = line.indexOf(key)
        if (start < 0) return null
        val from = start + key.length
        val end = line.indexOf(' ', from).let { if (it < 0) line.length else it }
        return line.substring(from, end).trim().ifEmpty { null }
    }

    private fun unescape(value: String): String = value.replace("\\040", " ").replace("\\011", "\t")
}

data class MapEntry(val perms: String, val path: String)

data class MountEntry(val mountPoint: String, val fstype: String, val source: String)

data class ProcInputDevice(
    val name: String,
    val vendor: Int?,
    val product: Int?,
    val bus: String,
    val handlers: String,
)

data class FingerprintIdentity(val brand: String, val product: String, val device: String)
