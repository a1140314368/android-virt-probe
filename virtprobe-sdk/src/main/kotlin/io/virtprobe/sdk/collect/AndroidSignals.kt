// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.sdk.collect

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import io.virtprobe.core.catalog.KnownSignals
import io.virtprobe.sdk.native.NativeEvidence
import java.io.File

/** Java 层能直接读到的身份、文件和包信息。和原生结果取并集，用来暴露只改了一层的 Hook。 */
internal object AndroidSignals {
    fun javaBuild(): Map<String, String> = mapOf(
        "BRAND" to Build.BRAND.orEmpty(),
        "MANUFACTURER" to Build.MANUFACTURER.orEmpty(),
        "MODEL" to Build.MODEL.orEmpty(),
        "DEVICE" to Build.DEVICE.orEmpty(),
        "PRODUCT" to Build.PRODUCT.orEmpty(),
        "HARDWARE" to Build.HARDWARE.orEmpty(),
        "BOARD" to Build.BOARD.orEmpty(),
        "FINGERPRINT" to Build.FINGERPRINT.orEmpty(),
        "HOST" to Build.HOST.orEmpty(),
        "TAGS" to Build.TAGS.orEmpty(),
        "TYPE" to Build.TYPE.orEmpty(),
        "DISPLAY" to Build.DISPLAY.orEmpty(),
        "ID" to Build.ID.orEmpty(),
        "USER" to Build.USER.orEmpty(),
        "BOOTLOADER" to Build.BOOTLOADER.orEmpty(),
        "SOC_MODEL" to if (Build.VERSION.SDK_INT >= 31) Build.SOC_MODEL.orEmpty() else "",
    )

    fun properties(native: NativeEvidence): Pair<Map<String, String>, String> {
        if (native.error == null) return native.properties to "native"
        val reflected = linkedMapOf<String, String>()
        var any = false
        for (key in KnownSignals.WATCHED_PROPERTIES) {
            val value = reflectSystemProperty(key)
            if (value != null) {
                reflected[key] = value
                any = true
            }
        }
        return if (any) reflected to "java-reflection-fallback" else emptyMap<String, String>() to "unavailable"
    }

    fun probeEmulatorPaths(native: NativeEvidence): Pair<List<String>, Map<String, String>> {
        val existing = linkedSetOf<String>()
        existing.addAll(native.existingPaths)
        val errors = native.pathErrors.toMutableMap()
        for (path in KnownSignals.EMULATOR_PATHS) {
            try {
                if (File(path).exists()) existing += path
            } catch (t: SecurityException) {
                errors.putIfAbsent(path, "EACCES:${t.message.orEmpty()}")
            }
        }
        return existing.toList() to errors
    }

    fun installed(context: Context, packages: List<String>): List<String> {
        val pm = context.packageManager
        return packages.filter { pkg ->
            try {
                pm.getPackageInfo(pkg, 0)
                true
            } catch (_: PackageManager.NameNotFoundException) {
                false
            }
        }
    }

    fun readText(path: String, maxBytes: Int = 64 * 1024): Pair<String, String?> {
        return try {
            val file = File(path)
            if (!file.exists()) return "" to "ABSENT"
            file.inputStream().use { input ->
                val buffer = ByteArray(maxBytes)
                val count = input.read(buffer)
                if (count <= 0) "" to null else String(buffer, 0, count, Charsets.ISO_8859_1) to null
            }
        } catch (t: SecurityException) {
            "" to "EACCES"
        } catch (t: Throwable) {
            "" to (t.message ?: t.javaClass.simpleName)
        }
    }

    fun prefer(nativeText: String, javaText: String): String = nativeText.ifBlank { javaText }

    /** 原生属性为空时的回退。隐藏 API 失败则返回空，调用方应显示无法读取，而不是编造。 */
    fun systemProperty(key: String): String {
        val reflected = reflectSystemProperty(key).orEmpty()
        if (reflected.isNotBlank()) return reflected
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("getprop", key))
            val value = process.inputStream.bufferedReader().use { it.readText() }.trim()
            process.waitFor()
            value
        } catch (_: Throwable) {
            ""
        }
    }

    private fun reflectSystemProperty(key: String): String? {
        return try {
            val clazz = Class.forName("android.os.SystemProperties")
            val method = clazz.getMethod("get", String::class.java, String::class.java)
            method.invoke(null, key, "") as? String
        } catch (_: Throwable) {
            null
        }
    }
}
