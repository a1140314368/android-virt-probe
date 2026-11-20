// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.core.json

import io.virtprobe.core.model.ModuleSummary
import io.virtprobe.core.model.ProbeReport
import io.virtprobe.core.model.SignalFinding
import java.util.Locale

/**
 * 把 [ProbeReport] 打成缩进 JSON。不依赖第三方库，保证核心模块在纯 JVM 上可测。
 */
object ReportJson {
    fun stringify(report: ProbeReport): String = render(report.toNode())

    private fun ProbeReport.toNode(): J.Obj = J.Obj(
        listOf(
            "schemaVersion" to J.Num(schemaVersion.toLong()),
            "reportId" to J.Str(reportId),
            "generatedAtEpochMs" to J.Num(generatedAtEpochMs),
            "verdict" to J.Str(verdict.name),
            "verdictLabelZh" to J.Str(verdict.labelZh),
            "riskScore" to J.Num(riskScore.toLong()),
            "riskBandZh" to J.Str(riskBandZh),
            "conclusionTitleZh" to J.Str(conclusionTitleZh),
            "conclusionSummaryZh" to J.Str(conclusionSummaryZh),
            "checkCount" to J.Num(checkCount.toLong()),
            "anomalyCount" to J.Num(anomalyCount.toLong()),
            "scoreBreakdownZh" to J.Str(scoreBreakdownZh),
            "moduleSummaries" to J.Arr(moduleSummaries.map { it.toNode() }),
            "findings" to J.Arr(findings.map { it.toNode() }),
        ),
    )

    private fun ModuleSummary.toNode(): J.Obj = J.Obj(
        listOf(
            "category" to J.Str(category.name),
            "titleZh" to J.Str(category.titleZh),
            "enabled" to J.Bool(enabled),
            "checkedCount" to J.Num(checkedCount.toLong()),
            "anomalyCount" to J.Num(anomalyCount.toLong()),
            "mediumOrAboveCount" to J.Num(mediumOrAboveCount.toLong()),
            "highestSeverity" to J.Str(highestSeverity.name),
            "statusZh" to J.Str(statusZh),
        ),
    )

    private fun SignalFinding.toNode(): J.Obj = J.Obj(
        listOf(
            "signalId" to J.Str(signalId),
            "category" to J.Str(category.name),
            "categoryTitleZh" to J.Str(category.titleZh),
            "severity" to J.Str(severity.name),
            "severityLabelZh" to J.Str(severity.labelZh),
            "confidence" to J.Dbl(confidence),
            "detected" to J.Bool(detected),
            "titleZh" to J.Str(titleZh),
            "summaryZh" to J.Str(summaryZh),
            "observedDataZh" to J.Str(observedDataZh),
            "expectedBaselineZh" to J.Str(expectedBaselineZh),
            "recommendationZh" to J.Str(recommendationZh),
            "sourceAttribution" to J.Str(sourceAttribution),
            "rawEvidence" to J.Obj(rawEvidence.map { (k, v) -> k to J.Str(v) }),
        ),
    )

    private fun render(node: J): String {
        val sb = StringBuilder()
        write(sb, node, 0)
        sb.append('\n')
        return sb.toString()
    }

    private fun write(sb: StringBuilder, node: J, indent: Int) {
        when (node) {
            is J.Str -> sb.append('"').append(escape(node.v)).append('"')
            is J.Num -> sb.append(node.v)
            is J.Dbl -> sb.append(formatDouble(node.v))
            is J.Bool -> sb.append(if (node.v) "true" else "false")
            is J.Arr -> {
                if (node.v.isEmpty()) {
                    sb.append("[]")
                    return
                }
                sb.append("[\n")
                node.v.forEachIndexed { index, child ->
                    sb.append(indentText(indent + 1))
                    write(sb, child, indent + 1)
                    if (index != node.v.lastIndex) sb.append(',')
                    sb.append('\n')
                }
                sb.append(indentText(indent)).append(']')
            }
            is J.Obj -> {
                if (node.v.isEmpty()) {
                    sb.append("{}")
                    return
                }
                sb.append("{\n")
                node.v.forEachIndexed { index, (key, child) ->
                    sb.append(indentText(indent + 1))
                    sb.append('"').append(escape(key)).append("\": ")
                    write(sb, child, indent + 1)
                    if (index != node.v.lastIndex) sb.append(',')
                    sb.append('\n')
                }
                sb.append(indentText(indent)).append('}')
            }
        }
    }

    private fun indentText(level: Int): String = "  ".repeat(level)

    private fun formatDouble(value: Double): String {
        if (value.isNaN() || value.isInfinite()) return "0"
        val raw = String.format(Locale.US, "%.4f", value)
        return raw.trimEnd('0').trimEnd('.').ifEmpty { "0" }
    }

    private fun escape(value: String): String {
        val sb = StringBuilder(value.length + 8)
        for (ch in value) {
            when (ch) {
                '\\' -> sb.append("\\\\")
                '"' -> sb.append("\\\"")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> {
                    if (ch.code < 0x20) {
                        sb.append("\\u")
                        sb.append(ch.code.toString(16).padStart(4, '0'))
                    } else {
                        sb.append(ch)
                    }
                }
            }
        }
        return sb.toString()
    }

    private sealed interface J {
        data class Str(val v: String) : J
        data class Num(val v: Long) : J
        data class Dbl(val v: Double) : J
        data class Bool(val v: Boolean) : J
        data class Arr(val v: List<J>) : J
        data class Obj(val v: List<Pair<String, J>>) : J
    }
}
