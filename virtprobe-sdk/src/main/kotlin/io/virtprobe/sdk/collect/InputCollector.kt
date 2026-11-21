// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.sdk.collect

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.ActivityManager
import android.content.Context
import android.provider.Settings
import android.os.Build
import android.view.InputDevice
import io.virtprobe.core.catalog.KnownSignals
import io.virtprobe.core.model.InputAuditSnapshot
import io.virtprobe.core.model.InputDeviceFact
import io.virtprobe.core.model.NodeVisibility
import io.virtprobe.sdk.native.NativeEvidence

internal object InputCollector {
    fun collect(context: Context, native: NativeEvidence): InputAuditSnapshot {
        val javaProc = AndroidSignals.readText("/proc/bus/input/devices", 32 * 1024)
        val procText = when {
            native.inputDevices.isNotBlank() -> native.inputDevices
            javaProc.second == null -> javaProc.first
            else -> null
        }
        val procError = when {
            native.inputError.isNotBlank() && native.inputDevices.isBlank() -> native.inputError
            javaProc.second != null && procText.isNullOrBlank() -> javaProc.second
            else -> null
        }
        return InputAuditSnapshot(
            devices = devices(),
            procBusInputText = procText,
            procBusReadError = procError,
            uinputVisibility = visibility(native.uinput),
            inputEventNodes = native.eventNodes,
            inputNodeError = native.pathErrors["/dev/input"].orEmpty().ifBlank { null },
            enabledAccessibilityServices = accessibility(context),
            installedAutomationPackages = AndroidSignals.installed(context, KnownSignals.AUTOMATION_PACKAGES),
            runningProcessNames = processes(context),
            instrumentationClassName = instrumentation(),
        )
    }

    private fun devices(): List<InputDeviceFact> {
        val ids = InputDevice.getDeviceIds()
        val out = ArrayList<InputDeviceFact>(ids.size)
        for (index in ids.indices) {
            val device = InputDevice.getDevice(ids[index]) ?: continue
            out += InputDeviceFact(
                id = device.id,
                name = device.name.orEmpty(),
                descriptor = device.descriptor.orEmpty(),
                vendorId = device.vendorId,
                productId = device.productId,
                isVirtual = device.isVirtual,
                isExternal = external(device),
                sources = device.sources,
            )
        }
        return out
    }

    private fun external(device: InputDevice): Boolean {
        if (Build.VERSION.SDK_INT < 29) return false
        return try {
            InputDevice::class.java.getMethod("isExternal").invoke(device) as Boolean
        } catch (_: Throwable) {
            false
        }
    }

    private fun visibility(state: String): NodeVisibility = when (state) {
        "PRESENT" -> NodeVisibility.PRESENT
        "ABSENT" -> NodeVisibility.ABSENT
        "PERMISSION_DENIED" -> NodeVisibility.PERMISSION_DENIED
        else -> NodeVisibility.UNKNOWN
    }

    private fun accessibility(context: Context): List<String> {
        val fromSettings = try {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
                .orEmpty()
                .split(':')
                .filter { it.isNotBlank() }
        } catch (_: Throwable) {
            emptyList()
        }
        val fromManager = try {
            val manager = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as android.view.accessibility.AccessibilityManager
            manager.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
                .mapNotNull { it.resolveInfo?.serviceInfo?.let { info -> "${info.packageName}/${info.name}" } }
        } catch (_: Throwable) {
            emptyList()
        }
        return (fromSettings + fromManager).distinct()
    }

    private fun processes(context: Context): List<String> {
        return try {
            val manager = context.getSystemService(ActivityManager::class.java) ?: return emptyList()
            @Suppress("DEPRECATION")
            manager.runningAppProcesses?.map { it.processName }.orEmpty()
        } catch (_: Throwable) {
            emptyList()
        }
    }

    private fun instrumentation(): String? {
        return try {
            val threadClass = Class.forName("android.app.ActivityThread")
            val current = threadClass.getDeclaredMethod("currentActivityThread").invoke(null) ?: return null
            val field = threadClass.getDeclaredField("mInstrumentation")
            field.isAccessible = true
            field.get(current)?.javaClass?.name
        } catch (_: Throwable) {
            null
        }
    }
}
