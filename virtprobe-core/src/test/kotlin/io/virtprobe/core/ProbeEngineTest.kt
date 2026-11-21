// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.core

import io.virtprobe.core.catalog.KnownSignals
import io.virtprobe.core.emulator.EmulatorRules
import io.virtprobe.core.engine.EngineConfig
import io.virtprobe.core.engine.ProbeEngine
import io.virtprobe.core.model.CLEAN_RECOMMENDATION_ZH
import io.virtprobe.core.model.DisplayFact
import io.virtprobe.core.model.DisplayFlagBits
import io.virtprobe.core.model.EnvironmentVerdict
import io.virtprobe.core.model.InputEventBits
import io.virtprobe.core.model.InputSourceBits
import io.virtprobe.core.model.MotionSample
import io.virtprobe.core.model.ProbeSnapshots
import io.virtprobe.core.model.Severity
import io.virtprobe.core.model.SignalCategory
import io.virtprobe.core.model.SignalFinding
import io.virtprobe.core.model.VirtualDisplaySnapshot
import io.virtprobe.core.report.ReportComposer
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

class ProbeEngineTest {
    @Test
    @DisplayName("真机基线不命中中高危，结论与三要素齐全")
    fun realDeviceBaseline() {
        val report = ProbeEngine.evaluate(realSnapshots(), EngineConfig(clockEpochMs = 1_700_000_000_000))
        assertEquals(EnvironmentVerdict.REAL_DEVICE, report.verdict)
        assertEquals("未发现明显异常信号", report.conclusionTitleZh)
        assertTrue(report.conclusionSummaryZh.contains("不能单独证明"))
        assertEquals(0, report.riskScore)
        assertEquals("低", report.riskBandZh)
        assertEquals("vp-1700000000000", report.reportId)
        assertTrue(report.anomalyCount == 0)
        assertTrue(report.findings.size > 40)
        report.findings.forEach { it.assertNarrative() }
        assertTrue(report.moduleSummaries.all { it.enabled && it.statusZh == "正常" })
        assertTrue(report.conclusionSummaryZh.contains("未命中"))
    }

    @Test
    @DisplayName("工作资料只有非 0 用户时仍判真机，并保留低敏提示")
    fun workProfileStaysRealDevice() {
        val report = ProbeEngine.evaluate(
            realSnapshots().copy(container = realContainerSnapshot(userId = 10)),
            EngineConfig(clockEpochMs = 20),
        )
        val user = report.findings.single { it.signalId == "ctn.user.id" }
        assertTrue(user.detected)
        assertEquals(Severity.LOW, user.severity)
        assertTrue(user.observedDataZh.contains("userId=10"))
        assertEquals(EnvironmentVerdict.REAL_DEVICE, report.verdict)
        assertTrue(report.conclusionSummaryZh.contains("低敏提示"))
        assertEquals("低敏提示 1 项", report.moduleSummaries.single { it.category == SignalCategory.CONTAINER }.statusZh)
    }

    @Test
    @DisplayName("QEMU 属性与管道同时命中时结论为模拟器，并写出基线原句")
    fun qemuBecomesEmulator() {
        val snapshot = realEmulatorSnapshot().copy(
            nativeProperties = realProperties() + mapOf(
                "ro.kernel.qemu" to "1",
                "ro.boot.qemu" to "1",
                "ro.boot.qemu.avd_name" to "Pixel_Fold_API_34",
                "ro.hardware" to "ranchu",
                "ro.build.characteristics" to "emulator",
            ),
            javaBuild = realBuild() + mapOf("HARDWARE" to "ranchu", "FINGERPRINT" to "google/sdk_gphone64_arm64/emu64a:14/UE1A.230829.036/123:userdebug/dev-keys"),
            existingPaths = listOf("/dev/qemu_pipe", "/dev/socket/qemud"),
            glRenderer = "Android Emulator OpenGL ES Translator (SwiftShader)",
            cpuInfo = "processor : 0\nflags : hypervisor\nmodel name : QEMU Virtual CPU\n",
            sensorNames = listOf("Goldfish 3-axis Accelerometer"),
            accelerometerSamples = List(6) { io.virtprobe.core.model.AccelSample(0f, 0f, 0f) },
            batteryTemperatureTenthsC = 0,
            batteryVoltageMv = 0,
            installedPackages = listOf("com.bluestacks.appmart"),
        )
        val findings = EmulatorRules.evaluate(snapshot)
        findings.forEach { it.assertNarrative() }
        val qemu = findings.single { it.signalId == "emu.prop.qemu" }
        assertTrue(qemu.detected)
        assertEquals(Severity.CRITICAL, qemu.severity)
        assertTrue(qemu.observedDataZh.contains("Pixel_Fold_API_34"))
        assertTrue(qemu.expectedBaselineZh.contains("ro.kernel.qemu 与 ro.boot.qemu 应为空或 0"))
        val pipes = findings.single { it.signalId == "emu.file.nodes" }
        assertTrue(pipes.detected)
        assertTrue(pipes.expectedBaselineZh.contains("真实物理手机不应出现 QEMU 管道节点"))
        assertTrue(pipes.recommendationZh.contains("高危虚拟环境信号，建议阻断敏感操作或触发二次实人校验"))
        assertTrue(findings.single { it.signalId == "emu.gl.renderer" }.detected)
        assertTrue(findings.single { it.signalId == "emu.sensor.accel" }.detected)
        assertTrue(findings.single { it.signalId == "emu.battery.static" }.detected)
        assertTrue(findings.single { it.signalId == "emu.pkg.known" }.observedDataZh.contains("com.bluestacks.appmart"))

        val report = ProbeEngine.evaluate(ProbeSnapshots(emulator = snapshot), EngineConfig(clockEpochMs = 7))
        assertEquals(EnvironmentVerdict.EMULATOR_OR_VM, report.verdict)
        assertEquals("疑似模拟器或虚拟机", report.conclusionTitleZh)
        assertTrue(report.riskScore in 50..100)
    }

    @Test
    @DisplayName("平行空间路径、异源映射和宿主栈同时出现时判为虚拟容器")
    fun parallelSpaceContainer() {
        val snapshot = realContainerSnapshot().copy(
            dataDir = "/data/user/0/com.lbe.parallel.intl/virtual/data/user/0/$SAMPLE_PKG",
            sourceDir = "/data/user/0/com.lbe.parallel.intl/virtual/data/app/$SAMPLE_PKG/base.apk",
            packagesForUid = listOf(SAMPLE_PKG, "com.lbe.parallel.intl"),
            cmdline = "com.lbe.parallel.intl",
            mapsText = """
                70a0-70b0 r-xp 00000000 fd:00 1 /data/user/0/com.lbe.parallel.intl/virtual/data/app/$SAMPLE_PKG/base.apk
                70c0-70d0 r-xp 00000000 fd:00 2 /data/app/~~x==/com.lbe.parallel.intl-y==/base.apk
                70e0-70f0 r-xp 00000000 fd:00 3 /data/app/~~x==/com.lbe.parallel.intl-y==/lib/arm64/libva++.so
            """.trimIndent(),
            mountInfoText = "50 1 253:8 / /data/user/0/$SAMPLE_PKG rw - ext4 /data/user/0/com.lbe.parallel.intl/virtual rw",
            environText = "VA_VERSION=1\u0000CLASSPATH=/data/app/com.lbe.parallel.intl/base.apk",
            classLoaderDexPaths = listOf("/data/user/0/com.lbe.parallel.intl/virtual/data/app/$SAMPLE_PKG/base.apk"),
            stackFrames = listOf("com.lody.virtual.client.VClient.startup"),
        )
        val report = ProbeEngine.evaluate(ProbeSnapshots(container = snapshot), EngineConfig(clockEpochMs = 8))
        assertEquals(EnvironmentVerdict.VIRTUAL_CONTAINER, report.verdict)
        assertEquals("疑似应用内虚拟容器", report.conclusionTitleZh)
        val data = report.findings.single { it.signalId == "ctn.path.data" }
        assertEquals(Severity.CRITICAL, data.severity)
        assertTrue(data.observedDataZh.contains("com.lbe.parallel.intl"))
        assertTrue(report.findings.single { it.signalId == "ctn.maps.foreign" }.detected)
        assertTrue(report.findings.single { it.signalId == "ctn.stack.framework" }.detected)
        assertTrue(report.findings.single { it.signalId == "ctn.environ.marker" }.observedDataZh.contains("VA_VERSION"))
        report.findings.forEach { it.assertNarrative() }
    }

    @Test
    @DisplayName("模拟器高危与容器高危同时出现时升为虚拟化环境")
    fun emulatorPlusContainerIsVirtualized() {
        val emulator = realEmulatorSnapshot().copy(
            nativeProperties = realProperties() + mapOf("ro.kernel.qemu" to "1", "ro.hardware" to "goldfish"),
            existingPaths = listOf("/dev/qemu_pipe"),
        )
        val container = realContainerSnapshot().copy(
            dataDir = "/data/user/0/io.virtualapp/virtual/data/user/0/$SAMPLE_PKG",
            cmdline = "io.virtualapp",
        )
        val report = ProbeEngine.evaluate(
            ProbeSnapshots(emulator = emulator, container = container),
            EngineConfig(clockEpochMs = 9),
        )
        assertEquals(EnvironmentVerdict.VIRTUALIZED_ENVIRONMENT, report.verdict)
        assertEquals("疑似虚拟化环境", report.conclusionTitleZh)
        assertTrue(report.scoreBreakdownZh.contains("跨维度印证加分"))
        assertTrue(report.riskScore > 50)
    }

    @Test
    @DisplayName("scrcpy 虚拟屏与屏幕采集回调给出投屏建议，总判为可疑")
    fun scrcpyDisplay() {
        val snapshot = VirtualDisplaySnapshot(
            displays = listOf(
                DisplayFact(0, "内置屏幕", 0, 1080, 2400, 420, 120f, true),
                DisplayFact(
                    displayId = 8,
                    name = "scrcpy",
                    flags = DisplayFlagBits.FLAG_PRESENTATION or DisplayFlagBits.FLAG_SECURE,
                    widthPx = 1080,
                    heightPx = 1920,
                    densityDpi = 0,
                    refreshHz = 0f,
                    isDefault = false,
                ),
            ),
            screenCaptureNotified = true,
            projectMediaMode = "MODE_ALLOWED",
            projectAudioMode = "MODE_DEFAULT",
            remoteRouteNames = listOf("客厅的 Chromecast"),
            selectedRemoteRoute = "客厅的 Chromecast",
            wifiDisplayOn = true,
        )
        val report = ProbeEngine.evaluate(ProbeSnapshots(virtualDisplay = snapshot), EngineConfig(clockEpochMs = 10))
        assertEquals(EnvironmentVerdict.SUSPICIOUS, report.verdict)
        val inventory = report.findings.single { it.signalId == "vd.display.inventory" }
        assertEquals(Severity.HIGH, inventory.severity)
        assertTrue(inventory.observedDataZh.contains("scrcpy"))
        assertTrue(inventory.recommendationZh.contains("检测到活跃投屏/虚拟副屏，建议对当前页面开启防截屏保护并提示关闭投屏"))
        assertTrue(report.findings.single { it.signalId == "vd.capture.callback" }.detected)
        assertTrue(report.findings.single { it.signalId == "vd.display.geometry" }.detected)
        assertTrue(report.findings.single { it.signalId == "vd.route.remote" }.observedDataZh.contains("Chromecast"))
        assertEquals("命中 6 项异常", report.moduleSummaries.single { it.category == SignalCategory.VIRTUAL_DISPLAY }.statusZh)
    }

    @Test
    @DisplayName("Build 被改写、指纹拼接、核数和软件密钥会拉高一致性风险")
    fun consistencyConflicts() {
        val snapshot = realConsistencySnapshot().copy(
            javaBuild = realBuild() + mapOf("MODEL" to "Pixel 8 Pro", "FINGERPRINT" to "not a fingerprint"),
            nativeProperties = realProperties() + mapOf(
                "ro.product.model" to "Pixel 8",
                "ro.build.fingerprint" to "broken",
                "ro.vendor.build.fingerprint" to "samsung/dm3q/dm3q:14/UP1A.231005.007/100:user/release-keys",
                "ro.boot.verifiedbootstate" to "orange",
                "ro.boot.flash.locked" to "0",
            ),
            javaProcCpuInfo = realCpuInfo(),
            nativeProcCpuInfo = realCpuInfo() + "\nHardware : goldfish\n",
            sysCpuPresent = "0-7",
            runtimeProcessors = 8,
            javaAbis = listOf("arm64-v8a"),
            unameMachine = "x86_64",
            keystore = io.virtprobe.core.model.KeystoreSnapshot(
                available = true,
                insideSecureHardware = false,
                attestationPresent = true,
                attestationSecurityLevel = "Software",
                verifiedBootState = "Unverified",
                deviceLocked = false,
            ),
            javaBattery = io.virtprobe.core.model.BatteryReading(0, 0, 50),
            sysBattery = io.virtprobe.core.model.BatteryReading(300, 4100, 50),
        )
        val report = ProbeEngine.evaluate(ProbeSnapshots(consistency = snapshot), EngineConfig(clockEpochMs = 11))
        assertTrue(report.findings.single { it.signalId == "con.cross.build" }.observedDataZh.contains("Pixel 8 Pro"))
        assertTrue(report.findings.single { it.signalId == "con.cross.cpuinfo" }.detected)
        assertTrue(report.findings.single { it.signalId == "con.fingerprint.format" }.detected)
        assertTrue(report.findings.single { it.signalId == "con.fingerprint.partitions" }.detected)
        assertTrue(report.findings.single { it.signalId == "con.boot.state" }.observedDataZh.contains("orange"))
        assertTrue(report.findings.single { it.signalId == "con.cpu.count" }.detected)
        assertTrue(report.findings.single { it.signalId == "con.abi.uname" }.detected)
        val tee = report.findings.single { it.signalId == "con.keystore.tee" }
        assertEquals(Severity.HIGH, tee.severity)
        assertTrue(tee.observedDataZh.contains("Software"))
        assertTrue(tee.expectedBaselineZh.contains("RootOfTrust"))
        assertTrue(report.findings.single { it.signalId == "con.battery.cross" }.detected)
        assertEquals(EnvironmentVerdict.SUSPICIOUS, report.verdict)
    }

    @Test
    @DisplayName("权限被拒绝的输入节点不算命中，虚拟触屏和自动化包算命中")
    fun inputAuditDistinguishesDenialFromHits() {
        val denied = realInputSnapshot().copy(
            procBusInputText = null,
            procBusReadError = "EACCES",
            uinputVisibility = NodeVisibilityDenied(),
        )
        val deniedReport = ProbeEngine.evaluate(ProbeSnapshots(input = denied), EngineConfig(clockEpochMs = 12))
        assertFalse(deniedReport.findings.single { it.signalId == "in.native.proc" }.detected)
        assertTrue(deniedReport.findings.single { it.signalId == "in.native.proc" }.observedDataZh.contains("EACCES"))
        assertFalse(deniedReport.findings.single { it.signalId == "in.native.uinput" }.detected)

        val hostile = realInputSnapshot().copy(
            devices = listOf(
                io.virtprobe.core.model.InputDeviceFact(
                    id = 1,
                    name = "scrcpy",
                    vendorId = 0,
                    productId = 0,
                    isVirtual = true,
                    sources = InputSourceBits.SOURCE_TOUCHSCREEN,
                ),
                io.virtprobe.core.model.InputDeviceFact(
                    id = 2,
                    name = "Virtual Mouse",
                    vendorId = 0,
                    productId = 0,
                    isVirtual = true,
                    sources = InputSourceBits.SOURCE_MOUSE,
                ),
            ),
            procBusInputText = "N: Name=\"uinput-goldfish\"\nH: Handlers=event0\n",
            uinputVisibility = io.virtprobe.core.model.NodeVisibility.PRESENT,
            enabledAccessibilityServices = listOf("com.example.reader/.Service"),
            installedAutomationPackages = listOf("org.autojs.autojs"),
            instrumentationClassName = "androidx.test.runner.AndroidJUnitRunner",
        )
        val report = ProbeEngine.evaluate(ProbeSnapshots(input = hostile), EngineConfig(clockEpochMs = 13))
        assertTrue(report.findings.single { it.signalId == "in.dev.virtual" }.detected)
        assertTrue(report.findings.single { it.signalId == "in.dev.virtual" }.expectedBaselineZh.contains("真实手指触控应来自物理触控芯片"))
        assertTrue(report.findings.single { it.signalId == "in.dev.ids" }.detected)
        assertTrue(report.findings.single { it.signalId == "in.dev.shape" }.detected)
        assertTrue(report.findings.single { it.signalId == "in.native.proc" }.observedDataZh.contains("uinput-goldfish"))
        assertTrue(report.findings.single { it.signalId == "in.native.uinput" }.detected)
        assertEquals(Severity.LOW, report.findings.single { it.signalId == "in.a11y.enabled" }.severity)
        assertTrue(report.findings.single { it.signalId == "in.auto.packages" }.observedDataZh.contains("org.autojs.autojs"))
        assertTrue(report.findings.single { it.signalId == "in.instrumentation" }.detected)
        assertEquals(EnvironmentVerdict.SUSPICIOUS, report.verdict)
    }

    @Test
    @DisplayName("关闭的维度标记为未启用，不产生假的正常项")
    fun disabledModule() {
        val report = ProbeEngine.evaluate(
            realSnapshots(),
            EngineConfig(enableEmulator = false, enableInput = false, clockEpochMs = 14),
        )
        assertEquals("未启用", report.moduleSummaries.single { it.category == SignalCategory.EMULATOR }.statusZh)
        assertEquals("未启用", report.moduleSummaries.single { it.category == SignalCategory.INPUT }.statusZh)
        assertTrue(report.findings.none { it.category == SignalCategory.EMULATOR })
        assertEquals(EnvironmentVerdict.REAL_DEVICE, report.verdict)
    }

    @Test
    @DisplayName("JSON 导出保留三要素、结论，并正确转义引号")
    fun jsonExportRoundTrip() {
        val report = ProbeEngine.evaluate(realSnapshots(), EngineConfig(clockEpochMs = 15))
        val withQuote = report.copy(
            findings = report.findings + SignalFinding(
                signalId = "meta.quote",
                category = SignalCategory.CONSISTENCY,
                severity = Severity.LOW,
                confidence = 0.5,
                detected = true,
                titleZh = "转义",
                summaryZh = "摘要",
                observedDataZh = "看到了 \"引号\" 和换行",
                expectedBaselineZh = "基线",
                recommendationZh = "建议保留原文",
                rawEvidence = mapOf("raw" to "a\"b\\c\n"),
                sourceAttribution = "测试",
            ),
        )
        val text = withQuote.toPrettyJson()
        val json = JSONObject(text)
        assertEquals("未发现明显异常信号", json.getString("conclusionTitleZh"))
        assertTrue(json.getString("conclusionSummaryZh").contains("不能单独证明"))
        assertTrue(json.getString("conclusionSummaryZh").isNotBlank())
        val findings = json.getJSONArray("findings")
        val first = findings.getJSONObject(0)
        assertTrue(first.getString("observedDataZh").isNotBlank())
        assertTrue(first.getString("expectedBaselineZh").isNotBlank())
        assertTrue(first.getString("recommendationZh").isNotBlank())
        val quoted = (0 until findings.length()).map { findings.getJSONObject(it) }.single { it.getString("signalId") == "meta.quote" }
        assertEquals("看到了 \"引号\" 和换行", quoted.getString("observedDataZh"))
        assertEquals("a\"b\\c\n", quoted.getJSONObject("rawEvidence").getString("raw"))
        assertTrue(KnownSignals.WATCHED_PROPERTIES.contains("ro.kernel.qemu"))
        assertTrue(KnownSignals.EMULATOR_PATHS.contains("/dev/qemu_pipe"))
    }

    @Test
    @DisplayName("大量严重项的风险分封顶为 100")
    fun scoreCapsAt100() {
        val findings = (1..8).map { index ->
            SignalFinding(
                signalId = "emu.fake.$index",
                category = SignalCategory.EMULATOR,
                severity = Severity.CRITICAL,
                confidence = 1.0,
                detected = true,
                titleZh = "严重$index",
                summaryZh = "摘要",
                observedDataZh = "数据$index",
                expectedBaselineZh = "基线",
                recommendationZh = "建议阻断",
                rawEvidence = emptyMap(),
                sourceAttribution = "测试",
            )
        }
        val report = ReportComposer.compose(findings, setOf(SignalCategory.EMULATOR), 99)
        assertEquals(100, report.riskScore)
        assertEquals("严重", report.riskBandZh)
        assertEquals(EnvironmentVerdict.EMULATOR_OR_VM, report.verdict)
    }

    private fun NodeVisibilityDenied() = io.virtprobe.core.model.NodeVisibility.PERMISSION_DENIED

    private fun SignalFinding.assertNarrative() {
        assertTrue(signalId.isNotBlank())
        assertTrue(titleZh.isNotBlank(), signalId)
        assertTrue(summaryZh.isNotBlank(), signalId)
        assertTrue(observedDataZh.isNotBlank(), signalId)
        assertTrue(expectedBaselineZh.isNotBlank(), signalId)
        assertTrue(recommendationZh.isNotBlank(), signalId)
        assertTrue(sourceAttribution.isNotBlank(), signalId)
        if (!detected) {
            assertEquals(Severity.INFO, severity, signalId)
            assertEquals(0.0, confidence, signalId)
            val keepsLimitation = recommendationZh.contains("漏报") ||
                recommendationZh.contains("不要") ||
                recommendationZh.contains("未知")
            if (!keepsLimitation) {
                assertEquals(CLEAN_RECOMMENDATION_ZH, recommendationZh, signalId)
            }
        }
    }
}
