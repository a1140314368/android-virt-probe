// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.core

import io.virtprobe.core.input.InputEventAnalyzer
import io.virtprobe.core.model.InputEventBits
import io.virtprobe.core.model.InputSourceBits
import io.virtprobe.core.model.KeySample
import io.virtprobe.core.model.MotionSample
import io.virtprobe.core.model.Severity
import io.virtprobe.core.parse.ProcText
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

class InputAndParseTest {
    @Test
    @DisplayName("真实手指点击只给出物理来源结论")
    fun realFinger() {
        val sample = finger(action = InputEventBits.ACTION_UP, eventTime = 1_200, downTime = 1_000, pressure = 0.42f, touchMajor = 18f)
        val findings = InputEventAnalyzer.analyzeMotion(listOf(sample))
        assertTrue(findings.none { it.detected })
        val story = InputEventAnalyzer.narrateMotion(sample, findings)
        assertFalse(story.suspicious)
        assertEquals("本次输入更接近物理硬件来源", story.verdictZh)
        assertTrue(story.observedDataZh.contains("deviceId=4"))
        assertTrue(story.observedDataZh.contains("pressure=0.42"))
        assertTrue(story.expectedBaselineZh.contains("真实手指触控应来自物理触控芯片"))
    }

    @Test
    @DisplayName("deviceId 小于等于 0、遮挡、无障碍标志和空 source 都会被点名")
    fun injectedTouchFlags() {
        val sample = finger(
            deviceId = -1,
            source = 0,
            toolType = InputEventBits.TOOL_TYPE_UNKNOWN,
            flags = InputEventBits.FLAG_WINDOW_IS_OBSCURED or InputEventBits.FLAG_IS_ACCESSIBILITY_EVENT,
            isDeviceVirtual = true,
            deviceName = "scrcpy",
        )
        val findings = InputEventAnalyzer.analyzeMotion(listOf(sample))
        assertTrue(findings.any { it.signalId == "in.event.device" && it.severity == Severity.HIGH })
        assertTrue(findings.any { it.signalId == "in.event.obscured" })
        assertTrue(findings.any { it.signalId == "in.event.accessibility" && it.observedDataZh.contains("0x800") })
        assertTrue(findings.any { it.signalId == "in.event.source" })
        val story = InputEventAnalyzer.narrateMotion(sample, findings)
        assertTrue(story.suspicious)
        assertEquals("本次输入疑似虚拟注入或自动化", story.verdictZh)
        assertTrue(story.recommendationZh.contains("建议"))
    }

    @Test
    @DisplayName("零时长、恒定压力直线和等间隔点击会触发运动学")
    fun kinematics() {
        val zero = finger(action = InputEventBits.ACTION_UP, eventTime = 50, downTime = 50)
        val zeroFindings = InputEventAnalyzer.analyzeMotion(listOf(zero))
        assertTrue(zeroFindings.single().observedDataZh.contains("时长为 0"))

        val moves = (0 until 8).map { index ->
            finger(
                action = InputEventBits.ACTION_MOVE,
                x = index * 20f,
                y = 10f,
                pressure = 1f,
                size = 0f,
                touchMajor = 0f,
                eventTime = 1_000L + index * 16,
            )
        }
        val line = InputEventAnalyzer.analyzeMotion(moves)
        val text = line.single { it.signalId == "in.event.kinematics" }.observedDataZh
        assertTrue(text.contains("完全不变") || text.contains("零抖动直线"))

        val rhythmSample = finger(action = InputEventBits.ACTION_DOWN, eventTime = 500, downTime = 500)
        val rhythm = InputEventAnalyzer.analyzeMotion(
            history = listOf(rhythmSample),
            recentDownTimes = listOf(100, 200, 300, 400, 500),
        )
        assertTrue(rhythm.single().observedDataZh.contains("机械等间隔"))
    }

    @Test
    @DisplayName("软键盘的虚拟设备号只算低敏，不把本次按键判成注入")
    fun softKeyboard() {
        val sample = KeySample(
            keyCode = 29,
            action = 0,
            deviceId = InputEventBits.DEVICE_ID_VIRTUAL_KEYBOARD,
            source = InputSourceBits.SOURCE_KEYBOARD,
            flags = 0,
            eventTime = 10,
            downTime = 10,
            isDeviceVirtual = true,
            deviceName = "Virtual",
        )
        val findings = InputEventAnalyzer.analyzeKey(sample)
        assertEquals(Severity.LOW, findings.single().severity)
        val story = InputEventAnalyzer.narrateKey(sample, findings)
        assertFalse(story.suspicious)
        assertTrue(story.verdictZh.contains("软键盘"))
        assertTrue(story.observedDataZh.contains("deviceId=-1"))
    }

    @Test
    @DisplayName("proc 文本解析能数核、认挂载、拆输入设备")
    fun parsers() {
        assertEquals(8, ProcText.cpuPresentCount("0-7"))
        assertEquals(6, ProcText.cpuPresentCount("0-3,5,7"))
        assertNull(ProcText.cpuPresentCount("cpu"))
        assertEquals(2, ProcText.cpuinfoProcessorCount(realCpuInfo()))
        assertTrue(ProcText.cpuinfoHasHypervisor("processor : 0\nflags : fpu hypervisor\n"))
        val maps = ProcText.parseMaps("aaaa-bbbb r-xp 00000000 fd:00 9 /data/app/other/base.apk")
        assertEquals("/data/app/other/base.apk", maps.single().path)
        val mounts = ProcText.parseMountInfo("1 1 0:1 / /data/user/0/pkg rw - ext4 /dev/block/by-name/userdata rw")
        assertEquals("/data/user/0/pkg", mounts.single().mountPoint)
        val devices = ProcText.parseInputDevices(
            """
            I: Bus=0006 Vendor=0000 Product=0000 Version=0000
            N: Name="qwerty2"
            H: Handlers=event0

            """.trimIndent(),
        )
        assertEquals("qwerty2", devices.single().name)
        assertEquals(0, devices.single().vendor)
        assertTrue(ProcText.isPlausibleFingerprint(PIXEL_FINGERPRINT))
        assertFalse(ProcText.isPlausibleFingerprint("not a fingerprint"))
        assertEquals("shiba", ProcText.fingerprintIdentity(PIXEL_FINGERPRINT)?.device)
        assertTrue(ProcText.abiMatchesKernel("aarch64", "armeabi-v7a"))
        assertFalse(ProcText.abiMatchesKernel("x86_64", "arm64-v8a"))
        val env = ProcText.parseEnviron("VA_VERSION=1\u0000PATH=/sbin")
        assertEquals("1", env["VA_VERSION"])
    }

    private fun finger(
        action: Int = InputEventBits.ACTION_DOWN,
        deviceId: Int = 4,
        source: Int = InputSourceBits.SOURCE_TOUCHSCREEN,
        toolType: Int = InputEventBits.TOOL_TYPE_FINGER,
        flags: Int = 0,
        pressure: Float = 0.4f,
        size: Float = 0.08f,
        touchMajor: Float = 16f,
        x: Float = 120f,
        y: Float = 340f,
        eventTime: Long = 1_000,
        downTime: Long = 900,
        isDeviceVirtual: Boolean? = false,
        deviceName: String? = "fts_ts",
    ): MotionSample = MotionSample(
        action = action,
        deviceId = deviceId,
        source = source,
        toolType = toolType,
        flags = flags,
        pressure = pressure,
        size = size,
        touchMajor = touchMajor,
        x = x,
        y = y,
        eventTime = eventTime,
        downTime = downTime,
        isDeviceVirtual = isDeviceVirtual,
        deviceName = deviceName,
    )
}
