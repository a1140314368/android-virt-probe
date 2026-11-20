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
        EnvironmentVerdict.REAL_DEVICE -> "未发现明显虚拟环境异常，符合真机基线"
        EnvironmentVerdict.SUSPICIOUS -> "发现可疑虚拟环境信号，建议结合业务做二次校验"
        EnvironmentVerdict.EMULATOR_OR_VM -> "高概率运行于模拟器或虚拟机环境"
        EnvironmentVerdict.VIRTUAL_CONTAINER -> "高概率运行于应用内虚拟化容器或多开分身"
        EnvironmentVerdict.VIRTUALIZED_ENVIRONMENT -> "高概率运行于虚拟/模拟器环境"
    }

    private fun summaryOfVerdict(verdict: EnvironmentVerdict, anomalies: List<SignalFinding>): String {
        if (anomalies.isEmpty()) {
            return "五大维度均未命中异常。当前采集结果与真实物理手机基线一致，可按正常设备继续业务。"
        }
        val counted = SignalCategory.entries.mapNotNull { category ->
            val count = anomalies.count { it.category == category }
            if (count == 0) null else "${category.titleZh} $count 项"
        }
        val top = anomalies.maxBy { it.severity.ordinal }
        val lowOnly = anomalies.all { it.severity == Severity.LOW }
        val lead = if (verdict == EnvironmentVerdict.REAL_DEVICE && lowOnly) {
            "存在 ${anomalies.size} 项低敏提示（${counted.joinToString("、")}），未构成模拟器、容器或跨层篡改证据。"
        } else {
            "已命中${counted.joinToString("、")}。其中最需要先看的是「${top.titleZh}」。"
        }
        return "$lead${top.recommendationZh}"
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
