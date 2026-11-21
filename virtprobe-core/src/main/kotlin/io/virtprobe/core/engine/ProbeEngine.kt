// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.core.engine

import io.virtprobe.core.consistency.ConsistencyRules
import io.virtprobe.core.container.ContainerRules
import io.virtprobe.core.emulator.EmulatorRules
import io.virtprobe.core.input.InputDeviceRules
import io.virtprobe.core.model.ProbeReport
import io.virtprobe.core.model.ProbeSnapshots
import io.virtprobe.core.model.SignalCategory
import io.virtprobe.core.report.ReportComposer
import io.virtprobe.core.virtualdisplay.VirtualDisplayRules

/**
 * 规则总入口。采集层把快照填好后调用这里，单元测试也直接调用这里。
 *
 * @property enableEmulator 等开关只决定跑哪些维度。关闭的维度不会出现「假的正常项」。
 * @property clockEpochMs 报告时间。测试可以传入固定值。
 */
data class EngineConfig(
    val enableEmulator: Boolean = true,
    val enableContainer: Boolean = true,
    val enableVirtualDisplay: Boolean = true,
    val enableConsistency: Boolean = true,
    val enableInput: Boolean = true,
    val clockEpochMs: Long = System.currentTimeMillis(),
)

object ProbeEngine {
    fun evaluate(snapshots: ProbeSnapshots, config: EngineConfig = EngineConfig()): ProbeReport {
        val findings = buildList {
            if (config.enableEmulator && snapshots.emulator != null) {
                addAll(EmulatorRules.evaluate(snapshots.emulator))
            }
            if (config.enableContainer && snapshots.container != null) {
                addAll(ContainerRules.evaluate(snapshots.container))
            }
            if (config.enableVirtualDisplay && snapshots.virtualDisplay != null) {
                addAll(VirtualDisplayRules.evaluate(snapshots.virtualDisplay))
            }
            if (config.enableConsistency && snapshots.consistency != null) {
                addAll(ConsistencyRules.evaluate(snapshots.consistency))
            }
            if (config.enableInput && snapshots.input != null) {
                addAll(InputDeviceRules.evaluate(snapshots.input))
            }
            if (config.enableInput) {
                addAll(snapshots.liveInputFindings.filter { it.detected })
            }
        }
        val enabled = buildSet {
            if (config.enableEmulator && snapshots.emulator != null) add(SignalCategory.EMULATOR)
            if (config.enableContainer && snapshots.container != null) add(SignalCategory.CONTAINER)
            if (config.enableVirtualDisplay && snapshots.virtualDisplay != null) add(SignalCategory.VIRTUAL_DISPLAY)
            if (config.enableConsistency && snapshots.consistency != null) add(SignalCategory.CONSISTENCY)
            if (config.enableInput && (snapshots.input != null || snapshots.liveInputFindings.isNotEmpty())) {
                add(SignalCategory.INPUT)
            }
        }
        return ReportComposer.compose(findings, enabled, config.clockEpochMs)
    }
}
