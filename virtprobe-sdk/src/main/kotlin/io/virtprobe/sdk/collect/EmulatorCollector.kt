// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.sdk.collect

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.opengl.EGL14
import android.opengl.EGLConfig
import android.opengl.EGLContext
import android.opengl.EGLDisplay
import android.opengl.EGLSurface
import android.opengl.GLES20
import android.os.BatteryManager
import android.os.Handler
import android.os.HandlerThread
import io.virtprobe.core.catalog.KnownSignals
import io.virtprobe.core.model.AccelSample
import io.virtprobe.core.model.EmulatorSnapshot
import io.virtprobe.sdk.native.NativeEvidence
import java.net.NetworkInterface
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

internal object EmulatorCollector {
    fun sampleForScan(context: Context, timeoutMs: Long): List<AccelSample> = sampleAccelerometer(context, timeoutMs)

    fun collect(context: Context, native: NativeEvidence, sensorTimeoutMs: Long): EmulatorSnapshot {
        val (properties, origin) = AndroidSignals.properties(native)
        val (paths, errors) = AndroidSignals.probeEmulatorPaths(native)
        val javaCpu = AndroidSignals.readText("/proc/cpuinfo", 32 * 1024)
        val javaMaps = AndroidSignals.readText("/proc/self/maps", 48 * 1024)
        val gl = readGl()
        val battery = readBattery(context)
        return EmulatorSnapshot(
            javaBuild = AndroidSignals.javaBuild(),
            nativeProperties = properties,
            propertyOrigin = origin,
            existingPaths = paths,
            probedPaths = KnownSignals.EMULATOR_PATHS,
            pathErrors = errors,
            installedPackages = AndroidSignals.installed(context, KnownSignals.EMULATOR_PACKAGES),
            glRenderer = gl.renderer,
            glVendor = gl.vendor,
            glError = gl.error,
            cpuInfo = AndroidSignals.prefer(native.cpuinfo, javaCpu.first),
            mapsText = AndroidSignals.prefer(native.maps, javaMaps.first),
            sensorNames = sensorNames(context),
            accelerometerSamples = sampleAccelerometer(context, sensorTimeoutMs),
            batteryTemperatureTenthsC = battery.first,
            batteryVoltageMv = battery.second,
            networkInterfaceNames = networkNames(),
            nativeHints = native.hints,
        )
    }

    private fun sensorNames(context: Context): List<String> {
        val manager = context.getSystemService(SensorManager::class.java) ?: return emptyList()
        return manager.getSensorList(Sensor.TYPE_ALL).map { sensor ->
            listOf(sensor.name, sensor.vendor).filter { it.isNotBlank() }.joinToString(" / ")
        }
    }

    private fun sampleAccelerometer(context: Context, timeoutMs: Long): List<AccelSample> {
        if (timeoutMs <= 0) return emptyList()
        val manager = context.getSystemService(SensorManager::class.java) ?: return emptyList()
        val sensor = manager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) ?: return emptyList()
        val thread = HandlerThread("virtprobe-sensor")
        thread.start()
        val samples = java.util.Collections.synchronizedList(mutableListOf<AccelSample>())
        val latch = CountDownLatch(1)
        val listener = object : SensorEventListener {
            override fun onSensorChanged(event: SensorEvent) {
                val values = event.values
                if (values.size >= 3) samples.add(AccelSample(values[0], values[1], values[2]))
                if (samples.size >= 8) latch.countDown()
            }

            override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) = Unit
        }
        return try {
            manager.registerListener(listener, sensor, SensorManager.SENSOR_DELAY_GAME, Handler(thread.looper))
            latch.await(timeoutMs, TimeUnit.MILLISECONDS)
            samples.toList()
        } catch (_: Throwable) {
            emptyList()
        } finally {
            manager.unregisterListener(listener)
            thread.quitSafely()
        }
    }

    private fun readBattery(context: Context): Pair<Int?, Int?> {
        val intent = try {
            context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        } catch (_: Throwable) {
            null
        } ?: return null to null
        val temp = intent.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, Int.MIN_VALUE)
        val voltage = intent.getIntExtra(BatteryManager.EXTRA_VOLTAGE, Int.MIN_VALUE)
        return temp.takeIf { it != Int.MIN_VALUE } to voltage.takeIf { it != Int.MIN_VALUE }
    }

    private fun networkNames(): List<String> {
        return try {
            val interfaces = NetworkInterface.getNetworkInterfaces() ?: return emptyList()
            interfaces.toList().map { it.name }
        } catch (_: Throwable) {
            emptyList()
        }
    }

    private data class GlStrings(val renderer: String, val vendor: String, val error: String)

    private fun readGl(): GlStrings {
        var display: EGLDisplay = EGL14.EGL_NO_DISPLAY
        var context: EGLContext = EGL14.EGL_NO_CONTEXT
        var surface: EGLSurface = EGL14.EGL_NO_SURFACE
        return try {
            display = EGL14.eglGetDisplay(EGL14.EGL_DEFAULT_DISPLAY)
            if (display == EGL14.EGL_NO_DISPLAY) return GlStrings("", "", "eglGetDisplay 失败")
            val version = IntArray(2)
            if (!EGL14.eglInitialize(display, version, 0, version, 1)) {
                return GlStrings("", "", "eglInitialize 失败")
            }
            val attrib = intArrayOf(
                EGL14.EGL_RENDERABLE_TYPE, EGL14.EGL_OPENGL_ES2_BIT,
                EGL14.EGL_SURFACE_TYPE, EGL14.EGL_PBUFFER_BIT,
                EGL14.EGL_NONE,
            )
            val configs = arrayOfNulls<EGLConfig>(1)
            val count = IntArray(1)
            if (!EGL14.eglChooseConfig(display, attrib, 0, configs, 0, 1, count, 0) || count[0] == 0 || configs[0] == null) {
                return GlStrings("", "", "eglChooseConfig 失败")
            }
            val contextAttrib = intArrayOf(EGL14.EGL_CONTEXT_CLIENT_VERSION, 2, EGL14.EGL_NONE)
            context = EGL14.eglCreateContext(display, configs[0], EGL14.EGL_NO_CONTEXT, contextAttrib, 0)
            val surfaceAttrib = intArrayOf(EGL14.EGL_WIDTH, 1, EGL14.EGL_HEIGHT, 1, EGL14.EGL_NONE)
            surface = EGL14.eglCreatePbufferSurface(display, configs[0], surfaceAttrib, 0)
            if (!EGL14.eglMakeCurrent(display, surface, surface, context)) {
                return GlStrings("", "", "eglMakeCurrent 失败")
            }
            GlStrings(
                renderer = GLES20.glGetString(GLES20.GL_RENDERER).orEmpty(),
                vendor = GLES20.glGetString(GLES20.GL_VENDOR).orEmpty(),
                error = "",
            )
        } catch (t: Throwable) {
            GlStrings("", "", t.message ?: t.javaClass.simpleName)
        } finally {
            if (display != EGL14.EGL_NO_DISPLAY) {
                EGL14.eglMakeCurrent(display, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_CONTEXT)
                if (surface != EGL14.EGL_NO_SURFACE) EGL14.eglDestroySurface(display, surface)
                if (context != EGL14.EGL_NO_CONTEXT) EGL14.eglDestroyContext(display, context)
                EGL14.eglTerminate(display)
            }
        }
    }
}
