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
        assertEquals(InputEventAnalyzer.HEAD_NONE, story.headlineZh)
        assertTrue(story.verdictZh.contains("不能证明是真人"))
        assertTrue(story.observedDataZh.contains("isVirtual=false"))
        assertTrue(story.observedDataZh.contains("FINGER"))
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
        assertEquals(InputEventAnalyzer.HEAD_CLUE, story.headlineZh)
        assertTrue(story.verdictZh.contains("观测"))
        assertTrue(story.notesZh.any { it.contains("遮挡不是注入") })
    }

    @Test
    @DisplayName("只有遮挡时不算注入")
    fun obscuredIsNotInjection() {
        val sample = finger(flags = InputEventBits.FLAG_WINDOW_IS_OBSCURED)
        val story = InputEventAnalyzer.narrateMotion(sample, InputEventAnalyzer.analyzeMotion(listOf(sample)))
        assertFalse(story.suspicious)
        assertEquals(InputEventAnalyzer.HEAD_NONE, story.headlineZh)
        assertTrue(story.notesZh.single().contains("遮挡不是注入"))
    }

    @Test
    @DisplayName("无障碍标志、虚拟键盘设备号、鼠标和未知工具类型分别是线索")
    fun sourceClues() {
        val flagged = finger(flags = InputEventBits.FLAG_IS_ACCESSIBILITY_EVENT, isDeviceVirtual = false)
        assertTrue(InputEventAnalyzer.analyzeMotion(listOf(flagged)).any { it.signalId == "in.event.accessibility" })

        val keyboardId = finger(deviceId = InputEventBits.DEVICE_ID_VIRTUAL_KEYBOARD, isDeviceVirtual = true, deviceName = "Virtual")
        assertTrue(InputEventAnalyzer.analyzeMotion(listOf(keyboardId)).any { it.summaryZh.contains("虚拟键盘设备号") })

        val mouse = finger(source = InputSourceBits.SOURCE_MOUSE, toolType = InputEventBits.TOOL_TYPE_MOUSE)
        val mouseStory = InputEventAnalyzer.narrateMotion(mouse, InputEventAnalyzer.analyzeMotion(listOf(mouse)))
        assertEquals(InputEventAnalyzer.HEAD_CLUE, mouseStory.headlineZh)
        assertTrue(mouseStory.verdictZh.contains("鼠标"))

        val unknown = finger(toolType = InputEventBits.TOOL_TYPE_UNKNOWN)
        assertTrue(InputEventAnalyzer.analyzeMotion(listOf(unknown)).any { it.summaryZh.contains("未知") })
    }

    @Test
    @DisplayName("模拟器设备名和压力恒值只导致证据不足，不编成注入")
    fun weakOrEmulator() {
        val zero = finger(action = InputEventBits.ACTION_UP, eventTime = 50, downTime = 50)
        val zeroStory = InputEventAnalyzer.narrateMotion(zero, InputEventAnalyzer.analyzeMotion(listOf(zero)))
        assertFalse(zeroStory.suspicious)
        assertEquals(InputEventAnalyzer.HEAD_WEAK, zeroStory.headlineZh)
        assertTrue(zeroStory.notesZh.any { it.contains("时刻相同") })

        val moves = (0 until 8).map { index ->
            finger(
                action = InputEventBits.ACTION_MOVE,
                x = index * 20f,
                y = 10f,
                pressure = 1f,
                size = 0f,
                touchMajor = 0f,
                eventTime = 1_000L + index * 16,
                pressureAvailable = true,
            )
        }
        val line = InputEventAnalyzer.analyzeMotion(moves)
        assertTrue(line.none { it.signalId == "in.event.kinematics" })
        val lineStory = InputEventAnalyzer.narrateMotion(moves, line)
        assertEquals(InputEventAnalyzer.HEAD_WEAK, lineStory.headlineZh)
        assertTrue(lineStory.notesZh.any { it.contains("压力值相同") })

        val unsupported = finger(pressure = 1f, pressureAvailable = false)
        val unsupportedStory = InputEventAnalyzer.narrateMotion(unsupported, InputEventAnalyzer.analyzeMotion(listOf(unsupported)))
        assertEquals(InputEventAnalyzer.HEAD_NONE, unsupportedStory.headlineZh)
        assertTrue(unsupportedStory.capabilityZh.contains("压力不可用"))

        val emulator = finger(deviceName = "virtio_input_multi_touch_1")
        val emulatorStory = InputEventAnalyzer.narrateMotion(emulator, InputEventAnalyzer.analyzeMotion(listOf(emulator)))
        assertFalse(emulatorStory.suspicious)
        assertEquals(InputEventAnalyzer.HEAD_WEAK, emulatorStory.headlineZh)
        assertTrue(emulatorStory.verdictZh.contains("不能当物理手指基线"))
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
        assertEquals(InputEventAnalyzer.HEAD_NONE, story.headlineZh)
        assertTrue(story.verdictZh.contains("软键盘"))
        assertTrue(story.verdictZh.contains("不能判作弊"))
        assertFalse(story.observedDataZh.contains("keyCode"))
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
        pressureAvailable: Boolean? = null,
        pointerCount: Int = 1,
        toolTypes: List<Int> = emptyList(),
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
        pressureAvailable = pressureAvailable,
        pointerCount = pointerCount,
        toolTypes = toolTypes,
    )
}
