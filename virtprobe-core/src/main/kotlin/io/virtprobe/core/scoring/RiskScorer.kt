// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.core.scoring

import io.virtprobe.core.model.Severity
import io.virtprobe.core.model.SignalFinding

/**
 * 把命中项收成 0 到 100 的风险分。
 *
 * 未命中项不计分。两个及以上维度同时出现中危命中时额外加分，
 * 因为跨层、跨维度互相印证比单条信号更值得抬高总分。
 */
object RiskScorer {
    fun score(findings: List<SignalFinding>): ScoreResult {
        val hits = findings.filter { it.detected }
        var raw = 0
        val parts = mutableListOf<String>()
        for (finding in hits) {
            val weight = weightOf(finding.severity)
            if (weight == 0) continue
            raw += weight
            parts += "${finding.signalId}+$weight"
        }
        val categories = hits
            .filter { it.severity.atLeast(Severity.MEDIUM) }
            .map { it.category }
            .distinct()
        var bonus = 0
        if (categories.size >= 2) bonus += 8
        if (categories.size >= 3) bonus += 8
        val total = (raw + bonus).coerceIn(0, 100)
        val breakdown = buildString {
            append("命中项权重合计 $raw")
            if (bonus > 0) append("，跨维度印证加分 $bonus")
            append("，封顶后为 $total。")
            if (parts.isEmpty()) append("没有会计分的命中项。")
        }
        return ScoreResult(score = total, breakdownZh = breakdown)
    }

    fun bandZh(score: Int): String = when {
        score >= 75 -> "严重"
        score >= 50 -> "高"
        score >= 25 -> "中"
        else -> "低"
    }

    private fun weightOf(severity: Severity): Int = when (severity) {
        Severity.INFO -> 0
        Severity.LOW -> 4
        Severity.MEDIUM -> 12
        Severity.HIGH -> 26
        Severity.CRITICAL -> 42
    }
}

data class ScoreResult(val score: Int, val breakdownZh: String)
