// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.sdk.collect

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.Sensor
import android.hardware.SensorManager
import android.os.BatteryManager
import io.virtprobe.core.model.BatteryReading
import io.virtprobe.core.model.ConsistencySnapshot
import io.virtprobe.core.model.SensorFact
import io.virtprobe.sdk.native.NativeEvidence

internal object ConsistencyCollector {
    fun collect(context: Context, native: NativeEvidence, samples: List<io.virtprobe.core.model.AccelSample>): ConsistencySnapshot {
        val javaCpu = AndroidSignals.readText("/proc/cpuinfo", 32 * 1024)
        val (properties, _) = AndroidSignals.properties(native)
        val errors = linkedMapOf<String, String>()
        javaCpu.second?.let { errors["cpuinfo"] = it }
        native.cpuinfoError.takeIf { it.isNotBlank() }?.let { errors.putIfAbsent("cpuinfo", it) }
        native.cpuPresentError.takeIf { it.isNotBlank() }?.let { errors["cpuPresent"] = it }
        return ConsistencySnapshot(
            javaBuild = AndroidSignals.javaBuild(),
            nativeProperties = properties,
            javaProcCpuInfo = javaCpu.first,
            nativeProcCpuInfo = native.cpuinfo,
            sysCpuPresent = native.cpuPresent.ifBlank { AndroidSignals.readText("/sys/devices/system/cpu/present", 64).first.trim() },
            runtimeProcessors = Runtime.getRuntime().availableProcessors(),
            javaAbis = android.os.Build.SUPPORTED_ABIS.toList(),
            unameMachine = native.unameMachine,
            sensors = sensors(context),
            accelerometerSamples = samples,
            javaBattery = javaBattery(context),
            sysBattery = sysBattery(native),
            keystore = KeystoreProbe.collect(),
            readErrors = errors,
        )
    }

    private fun sensors(context: Context): List<SensorFact> {
        val manager = context.getSystemService(SensorManager::class.java) ?: return emptyList()
        return manager.getSensorList(Sensor.TYPE_ALL).map { sensor ->
            SensorFact(type = sensor.type, name = sensor.name.orEmpty(), vendor = sensor.vendor.orEmpty())
        }
    }

    private fun javaBattery(context: Context): BatteryReading? {
        val intent = try {
            context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        } catch (_: Throwable) {
            null
        } ?: return null
        return BatteryReading(
            temperatureTenthsC = intent.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, Int.MIN_VALUE).takeIf { it != Int.MIN_VALUE },
            voltageMv = intent.getIntExtra(BatteryManager.EXTRA_VOLTAGE, Int.MIN_VALUE).takeIf { it != Int.MIN_VALUE },
            capacityPercent = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, Int.MIN_VALUE).takeIf { it != Int.MIN_VALUE },
        )
    }

    private fun sysBattery(native: NativeEvidence): BatteryReading {
        return BatteryReading(
            temperatureTenthsC = normalizeTemp(native.batteryTemp),
            voltageMv = normalizeVoltage(native.batteryVoltage),
            capacityPercent = native.batteryCapacity.toIntOrNull(),
        )
    }

    /** Android 的 temp 节点通常已经是 0.1℃。个别内核用毫摄氏度，超过 1000 时换算回来。 */
    private fun normalizeTemp(raw: String): Int? {
        val value = raw.trim().toIntOrNull() ?: return null
        return if (kotlin.math.abs(value) > 1000) value / 100 else value
    }

    /** voltage_now 通常是微伏。大于 100000 时换成毫伏，和 BatteryManager 对齐。 */
    private fun normalizeVoltage(raw: String): Int? {
        val value = raw.trim().toLongOrNull() ?: return null
        return if (value > 100_000L) (value / 1000L).toInt() else value.toInt()
    }
}
