// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.sdk.collect

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Debug
import android.provider.Settings
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import io.virtprobe.core.model.ProbeVisibility
import io.virtprobe.core.model.RuntimeSnapshot
import io.virtprobe.core.runtime.RuntimeRules
import io.virtprobe.sdk.native.NativeEvidence
import java.io.FileNotFoundException

internal object RuntimeCollector {
    private val binaries = listOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/debug_ramdisk/su",
        "/debug_ramdisk/magisk",
        "/data/adb/magisk",
        "/data/adb/ksu",
        "/data/adb/ap",
    )
    private val mountMarkers = listOf("magisk", "zygisk", "/data/adb/ksu", "/data/adb/ap", "/data/adb/modules")
    private val packages = listOf(
        "com.topjohnwu.magisk",
        "me.weishu.kernelsu",
        "me.bmax.apatch",
        "org.lsposed.manager",
        "de.robv.android.xposed.installer",
    )

    fun collect(context: Context, native: NativeEvidence): RuntimeSnapshot {
        val mounts = textOrDenied(native.mountinfo, native.mountinfoError, "/proc/self/mountinfo")
        val maps = textOrDenied(native.maps, native.mapsError, "/proc/self/maps")
        val unix = readDirect("/proc/net/unix", 256 * 1024)
        val status = readDirect("/proc/self/status", 16 * 1024)
        val enforce = readDirect("/sys/fs/selinux/enforce", 16)
        return RuntimeSnapshot(
            binaryProbes = binaries.associateWith { probe(it) },
            mountHits = hits(mounts.first, mountMarkers),
            mountState = mounts.second,
            mapHits = RuntimeRules.mapMarkers(maps.first),
            mapsState = maps.second,
            unixHits = RuntimeRules.unixMarkers(unix.first),
            unixState = when {
                unix.second?.contains("EACCES") == true || unix.second?.contains("Permission") == true ->
                    ProbeVisibility.DENIED
                unix.first.isNotBlank() -> ProbeVisibility.PRESENT
                // 空读不是可信的阴性：Android 上这张表不该是空的，空通常是被过滤。
                else -> ProbeVisibility.DENIED
            },
            tracerPid = RuntimeRules.parseTracerPid(status.first).let { pid ->
                if (pid != null) pid else if (status.second?.contains("EACCES") == true) null else pid
            },
            javaDebuggerConnected = runCatching { Debug.isDebuggerConnected() }.getOrNull(),
            selinuxEnforce = enforce.first.trim().ifBlank { null },
            securityPatch = Build.VERSION.SECURITY_PATCH.orEmpty(),
            buildTags = firstNonBlank(native.properties["ro.build.tags"], AndroidSignals.systemProperty("ro.build.tags"), Build.TAGS),
            roSecure = firstNonBlank(native.properties["ro.secure"], AndroidSignals.systemProperty("ro.secure")),
            roDebuggable = firstNonBlank(native.properties["ro.debuggable"], AndroidSignals.systemProperty("ro.debuggable")),
            adbEnabled = globalFlag(context, "adb_enabled"),
            vpnActive = vpn(context),
            httpProxy = proxy(context),
            cluePackages = AndroidSignals.installed(context, packages),
            nowEpochMs = System.currentTimeMillis(),
        )
    }

    private fun probe(path: String): ProbeVisibility = try {
        Os.access(path, OsConstants.F_OK)
        ProbeVisibility.PRESENT
    } catch (e: ErrnoException) {
        when (e.errno) {
            OsConstants.EACCES, OsConstants.EPERM -> ProbeVisibility.DENIED
            OsConstants.ENOENT -> ProbeVisibility.NOT_VISIBLE
            else -> ProbeVisibility.DENIED
        }
    } catch (_: SecurityException) {
        ProbeVisibility.DENIED
    }

    private fun textOrDenied(nativeText: String, nativeError: String, path: String): Pair<String, ProbeVisibility> {
        if (nativeText.isNotBlank()) return nativeText to ProbeVisibility.PRESENT
        if (nativeError.contains("EACCES", ignoreCase = true) || nativeError.contains("Permission", ignoreCase = true)) {
            return "" to ProbeVisibility.DENIED
        }
        val java = AndroidSignals.readText(path, 64 * 1024)
        return when {
            java.first.isNotBlank() -> java.first to ProbeVisibility.PRESENT
            java.second?.contains("EACCES", ignoreCase = true) == true -> "" to ProbeVisibility.DENIED
            else -> "" to ProbeVisibility.NOT_VISIBLE
        }
    }

    private fun hits(text: String, markers: List<String>): List<String> {
        if (text.isBlank()) return emptyList()
        val lower = text.lowercase()
        return markers.filter { lower.contains(it) }
    }

    private fun readDirect(path: String, maxBytes: Int): Pair<String, String?> = try {
        java.io.File(path).inputStream().use { input ->
            val buffer = ByteArray(maxBytes)
            val count = input.read(buffer)
            if (count <= 0) "" to null else String(buffer, 0, count, Charsets.ISO_8859_1) to null
        }
    } catch (_: FileNotFoundException) {
        "" to "ABSENT"
    } catch (t: SecurityException) {
        "" to "EACCES"
    } catch (t: Throwable) {
        val message = t.message.orEmpty()
        if (message.contains("EACCES", ignoreCase = true) || message.contains("Permission", ignoreCase = true)) {
            "" to "EACCES"
        } else {
            "" to (t.message ?: t.javaClass.simpleName)
        }
    }

    private fun firstNonBlank(vararg values: String?): String =
        values.firstOrNull { !it.isNullOrBlank() }.orEmpty()

    private fun globalFlag(context: Context, key: String): Boolean? = try {
        Settings.Global.getInt(context.contentResolver, key, -1).let { if (it < 0) null else it == 1 }
    } catch (_: Throwable) {
        null
    }

    private fun vpn(context: Context): Boolean? = try {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return null
        cm.allNetworks.any { network ->
            cm.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        }
    } catch (_: Throwable) {
        null
    }

    private fun proxy(context: Context): String? {
        val host = System.getProperty("http.proxyHost").orEmpty()
        val port = System.getProperty("http.proxyPort").orEmpty()
        if (host.isNotBlank()) return if (port.isBlank()) host else "$host:$port"
        return try {
            Settings.Global.getString(context.contentResolver, "http_proxy")
        } catch (_: Throwable) {
            null
        }
    }
}
