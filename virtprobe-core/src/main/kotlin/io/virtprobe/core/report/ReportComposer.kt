// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.core.report

import io.virtprobe.core.correlation.CorrelationEngine
import io.virtprobe.core.model.EnvironmentVerdict
import io.virtprobe.core.model.ModuleSummary
import io.virtprobe.core.model.ProbeReport
import io.virtprobe.core.model.Severity
import io.virtprobe.core.model.SignalCategory
import io.virtprobe.core.model.SignalFinding
import io.virtprobe.core.scoring.RiskScorer

/**
 * 把规则输出收成一份可展示的 [ProbeReport]，包括顶层中文结论和五个维度的状态。
 */
object ReportComposer {
    fun compose(
        findings: List<SignalFinding>,
        enabled: Set<SignalCategory>,
        generatedAtEpochMs: Long,
    ): ProbeReport {
        val ordered = findings.sortedWith(compareBy({ it.category.ordinal }, { it.signalId }))
        val scored = RiskScorer.score(ordered)
        val verdict = CorrelationEngine.verdict(ordered, scored.score)
        val anomalies = ordered.filter { it.detected }
        val summaries = SignalCategory.entries.map { category ->
            summaryOf(category, ordered.filter { it.category == category }, enabled.contains(category))
        }
        return ProbeReport(
            schemaVersion = 1,
            reportId = "vp-$generatedAtEpochMs",
            generatedAtEpochMs = generatedAtEpochMs,
            verdict = verdict,
            riskScore = scored.score,
            riskBandZh = RiskScorer.bandZh(scored.score),
            conclusionTitleZh = titleOf(verdict),
            conclusionSummaryZh = summaryOfVerdict(verdict, anomalies),
            checkCount = ordered.size,
            anomalyCount = anomalies.size,
            findings = ordered,
            moduleSummaries = summaries,
            scoreBreakdownZh = scored.breakdownZh,
        )
    }

    fun titleOf(verdict: EnvironmentVerdict): String = when (verdict) {
        EnvironmentVerdict.REAL_DEVICE -> "未发现明显异常信号"
        EnvironmentVerdict.SUSPICIOUS -> "发现可疑线索，建议复核"
        EnvironmentVerdict.EMULATOR_OR_VM -> "疑似模拟器或虚拟机"
        EnvironmentVerdict.VIRTUAL_CONTAINER -> "疑似应用内虚拟容器"
        EnvironmentVerdict.VIRTUALIZED_ENVIRONMENT -> "疑似虚拟化环境"
        EnvironmentVerdict.RUNTIME_CLUE -> "发现提权或注入线索"
    }

    private fun summaryOfVerdict(verdict: EnvironmentVerdict, anomalies: List<SignalFinding>): String {
        if (anomalies.isEmpty()) {
            return "未命中已知信号。未命中不能单独证明环境正常。"
        }
        val counted = SignalCategory.entries.mapNotNull { category ->
            val count = anomalies.count { it.category == category }
            if (count == 0) null else "${category.titleZh} $count 项"
        }
        val top = anomalies.maxBy { it.severity.ordinal }
        val lowOnly = anomalies.all { it.severity == Severity.LOW }
        val lead = if (verdict == EnvironmentVerdict.REAL_DEVICE && lowOnly) {
            "低敏提示 ${anomalies.size} 项。不足以说明环境异常。"
        } else {
            "已命中 ${counted.joinToString("、")}。优先看「${top.titleZh}」。"
        }
        return lead + top.recommendationZh
    }

    private fun summaryOf(category: SignalCategory, findings: List<SignalFinding>, enabled: Boolean): ModuleSummary {
        if (!enabled) {
            return ModuleSummary(
                category = category,
                enabled = false,
                checkedCount = 0,
                anomalyCount = 0,
                mediumOrAboveCount = 0,
                highestSeverity = Severity.INFO,
                statusZh = "未启用",
            )
        }
        val anomalies = findings.filter { it.detected }
        val medium = anomalies.count { it.severity.atLeast(Severity.MEDIUM) }
        val highest = anomalies.maxOfOrNull { it.severity } ?: Severity.INFO
        val status = when {
            anomalies.isEmpty() -> "正常"
            medium == 0 -> "低敏提示 ${anomalies.size} 项"
            else -> "命中 ${anomalies.size} 项异常"
        }
        return ModuleSummary(
            category = category,
            enabled = true,
            checkedCount = findings.size,
            anomalyCount = anomalies.size,
            mediumOrAboveCount = medium,
            highestSeverity = highest,
            statusZh = status,
        )
    }
}
