// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.core.correlation

import io.virtprobe.core.model.EnvironmentVerdict
import io.virtprobe.core.model.Severity
import io.virtprobe.core.model.SignalCategory
import io.virtprobe.core.model.SignalFinding

/**
 * 跨维度关联。单条中危投屏不会被说成「整机是模拟器」，
 * 模拟器高危和容器高危同时出现才会升到虚拟化环境。
 */
object CorrelationEngine {
    fun verdict(findings: List<SignalFinding>, score: Int): EnvironmentVerdict {
        val hits = findings.filter { it.detected && it.severity != Severity.INFO }
        if (hits.isEmpty()) return EnvironmentVerdict.REAL_DEVICE

        val emulatorStrong = strong(hits, SignalCategory.EMULATOR)
        val containerStrong = strong(hits, SignalCategory.CONTAINER)
        val activeCategories = hits
            .filter { it.severity.atLeast(Severity.MEDIUM) }
            .map { it.category }
            .toSet()

        if (emulatorStrong && containerStrong) return EnvironmentVerdict.VIRTUALIZED_ENVIRONMENT
        if (activeCategories.size >= 3 &&
            hits.any { it.severity.atLeast(Severity.HIGH) } &&
            (emulatorStrong || containerStrong)
        ) {
            return EnvironmentVerdict.VIRTUALIZED_ENVIRONMENT
        }
        if (emulatorStrong || countAtLeast(hits, SignalCategory.EMULATOR, Severity.MEDIUM) >= 3) {
            return EnvironmentVerdict.EMULATOR_OR_VM
        }
        if (containerStrong || countAtLeast(hits, SignalCategory.CONTAINER, Severity.MEDIUM) >= 2) {
            return EnvironmentVerdict.VIRTUAL_CONTAINER
        }
        if (strong(hits, SignalCategory.RUNTIME)) return EnvironmentVerdict.RUNTIME_CLUE
        val lowCount = hits.count { it.severity == Severity.LOW }
        if (hits.any { it.severity.atLeast(Severity.MEDIUM) } || score >= 25 || lowCount >= 3) {
            return EnvironmentVerdict.SUSPICIOUS
        }
        return EnvironmentVerdict.REAL_DEVICE
    }

    private fun strong(hits: List<SignalFinding>, category: SignalCategory): Boolean {
        return hits.any { it.category == category && it.severity.atLeast(Severity.HIGH) }
    }

    private fun countAtLeast(hits: List<SignalFinding>, category: SignalCategory, min: Severity): Int {
        return hits.count { it.category == category && it.severity.atLeast(min) }
    }
}
