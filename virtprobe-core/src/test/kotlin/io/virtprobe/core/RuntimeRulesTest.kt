// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.core

import io.virtprobe.core.engine.EngineConfig
import io.virtprobe.core.engine.ProbeEngine
import io.virtprobe.core.model.EnvironmentVerdict
import io.virtprobe.core.model.ProbeSnapshots
import io.virtprobe.core.model.ProbeVisibility
import io.virtprobe.core.model.RuntimeSnapshot
import io.virtprobe.core.model.Severity
import io.virtprobe.core.runtime.RuntimeRules
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RuntimeRulesTest {
    @Test
    fun devKeysAreAClue() {
        val finding = RuntimeRules.evaluate(realRuntimeSnapshot().copy(buildTags = "dev-keys"))
            .single { it.signalId == "rt.build.trust" }
        assertTrue(finding.detected)
        assertTrue(finding.summaryZh.contains("疑似"))
        assertTrue(finding.observedDataZh.contains("dev-keys"))
    }

    @Test
    fun cleanRuntimeIsNotAnAnomaly() {
        val findings = RuntimeRules.evaluate(realRuntimeSnapshot())
        assertTrue(findings.none { it.detected && it.severity >= Severity.LOW })
        val posture = findings.single { it.signalId == "rt.net.posture" }
        assertFalse(posture.detected)
        assertTrue(posture.expectedBaselineZh.contains("因设备"))
    }

    @Test
    fun deniedSuIsUnknownNotNormal() {
        val finding = RuntimeRules.evaluate(
            realRuntimeSnapshot().copy(
                binaryProbes = mapOf("/system/bin/su" to ProbeVisibility.DENIED),
            ),
        ).single { it.signalId == "rt.su.paths" }
        assertFalse(finding.detected)
        assertEquals("无法检查", finding.summaryZh)
        assertTrue(finding.observedDataZh.contains("拒绝读取"))
    }

    @Test
    fun visibleSuIsClueNotMaliciousVerdict() {
        val snapshot = realRuntimeSnapshot().copy(
            binaryProbes = mapOf("/system/bin/su" to ProbeVisibility.PRESENT),
            cluePackages = listOf("com.topjohnwu.magisk"),
        )
        val report = ProbeEngine.evaluate(
            ProbeSnapshots(runtime = snapshot),
            EngineConfig(clockEpochMs = 10),
        )
        val su = report.findings.single { it.signalId == "rt.su.paths" }
        assertEquals(Severity.HIGH, su.severity)
        assertTrue(su.summaryZh.contains("疑似"))
        assertTrue(su.recommendationZh.contains("不等于恶意"))
        assertEquals(EnvironmentVerdict.RUNTIME_CLUE, report.verdict)
        assertEquals("发现提权或注入线索", report.conclusionTitleZh)
        val pkg = report.findings.single { it.signalId == "rt.pkg.clue" }
        assertEquals(Severity.LOW, pkg.severity)
    }

    @Test
    fun vpnAndAdbAreNotAnomalies() {
        val finding = RuntimeRules.evaluate(
            realRuntimeSnapshot().copy(vpnActive = true, adbEnabled = true, httpProxy = "127.0.0.1:8080"),
        ).single { it.signalId == "rt.net.posture" }
        assertFalse(finding.detected)
        assertTrue(finding.observedDataZh.contains("VPN=开"))
        assertTrue(finding.summaryZh.contains("不等于异常"))
    }

    @Test
    fun permissiveSelinuxAndTracerAreSeparate() {
        val findings = RuntimeRules.evaluate(
            realRuntimeSnapshot().copy(selinuxEnforce = "0", tracerPid = 32, javaDebuggerConnected = false),
        )
        assertEquals("线索：SELinux 为 Permissive", findings.single { it.signalId == "rt.selinux.mode" }.summaryZh)
        assertTrue(findings.single { it.signalId == "rt.debug.tracer" }.detected)
        assertEquals("无法检查", RuntimeRules.evaluate(realRuntimeSnapshot().copy(selinuxEnforce = null))
            .single { it.signalId == "rt.selinux.mode" }.summaryZh)
    }

    @Test
    fun badPatchFormatIsLowAndOldPatchIsNotAnAnomaly() {
        val bad = RuntimeRules.evaluate(realRuntimeSnapshot().copy(securityPatch = "yesterday"))
            .single { it.signalId == "rt.patch.date" }
        assertTrue(bad.detected)
        assertEquals(Severity.LOW, bad.severity)
        val old = RuntimeRules.evaluate(
            realRuntimeSnapshot().copy(securityPatch = "2020-01-01", nowEpochMs = 1_763_600_000_000),
        ).single { it.signalId == "rt.patch.date" }
        assertFalse(old.detected)
        assertTrue(old.summaryZh.contains("因厂商而异"))
    }

    @Test
    fun tracerAndMapMarkersAvoidLooseMatches() {
        assertEquals(0, RuntimeRules.parseTracerPid("Name:\tapp\nTracerPid:\t0\n"))
        assertEquals(12, RuntimeRules.parseTracerPid("TracerPid: 12\n"))
        assertEquals(null, RuntimeRules.parseTracerPid("no tracer line"))
        assertTrue(RuntimeRules.mapMarkers("r-xp /data/local/tmp/frida-gadget.so").contains("frida-gadget"))
        assertTrue(RuntimeRules.mapMarkers("/data/local/tmp/re.frida.server/frida-agent-64.so").contains("frida-agent"))
        assertTrue(RuntimeRules.mapMarkers("callspd helper").isEmpty())
        assertTrue(RuntimeRules.mapMarkers("library fridahelper.so").isEmpty())
        assertEquals(listOf("frida-zymbiote"), RuntimeRules.unixMarkers("@/frida-zymbiote-abc"))
        assertTrue(RuntimeRules.unixMarkers("frida-helper").isEmpty())
    }

    @Test
    fun unixTableDeniedIsUnknownNotClear() {
        val finding = RuntimeRules.evaluate(
            realRuntimeSnapshot().copy(
                mapsState = ProbeVisibility.PRESENT,
                unixState = ProbeVisibility.DENIED,
            ),
        ).single { it.signalId == "rt.maps.inject" }
        assertFalse(finding.detected)
        assertEquals("无法检查", finding.summaryZh)
        assertTrue(finding.observedDataZh.contains("套接字表不可读"))
        assertTrue(finding.recommendationZh.contains("未知"))
    }

    @Test
    fun fridaZymbioteSocketIsAClue() {
        val finding = RuntimeRules.evaluate(
            realRuntimeSnapshot().copy(
                mapsState = ProbeVisibility.PRESENT,
                unixState = ProbeVisibility.PRESENT,
                unixHits = listOf("frida-zymbiote"),
            ),
        ).single { it.signalId == "rt.maps.inject" }
        assertTrue(finding.detected)
        assertTrue(finding.observedDataZh.contains("frida-zymbiote"))
    }

    @Test
    fun mapAndMountHitsStayClues() {
        val findings = RuntimeRules.evaluate(
            realRuntimeSnapshot().copy(
                mountHits = listOf("/debug_ramdisk/.magisk"),
                mountState = ProbeVisibility.PRESENT,
                mapHits = listOf("frida-gadget.so"),
                mapsState = ProbeVisibility.PRESENT,
            ),
        )
        assertTrue(findings.single { it.signalId == "rt.mount.markers" }.summaryZh.contains("疑似"))
        assertTrue(findings.single { it.signalId == "rt.maps.inject" }.recommendationZh.contains("隐藏框架"))
    }
}
