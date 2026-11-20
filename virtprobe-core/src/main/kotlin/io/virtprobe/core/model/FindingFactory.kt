// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.core.model

/** 未命中时统一使用的建议，避免每条规则各写一句空话。 */
const val CLEAN_RECOMMENDATION_ZH: String = "该项符合真机基线，无需额外处置。"

/** 高危虚拟环境的通用处置建议。具体规则可以改用更贴场景的句子。 */
const val BLOCK_SENSITIVE_RECOMMENDATION_ZH: String =
    "高危虚拟环境信号，建议阻断敏感操作或触发二次实人校验。"

/**
 * 构造一条信号。未命中时强制把级别降为信息、置信度降为 0，避免正常项进入风险分。
 */
fun finding(
    signalId: String,
    category: SignalCategory,
    severity: Severity,
    confidence: Double,
    detected: Boolean,
    titleZh: String,
    summaryZh: String,
    observedDataZh: String,
    expectedBaselineZh: String,
    recommendationZh: String,
    rawEvidence: Map<String, String> = emptyMap(),
    sourceAttribution: String,
): SignalFinding {
    return SignalFinding(
        signalId = signalId,
        category = category,
        severity = if (detected) severity else Severity.INFO,
        confidence = if (detected) confidence.coerceIn(0.0, 1.0) else 0.0,
        detected = detected,
        titleZh = titleZh,
        summaryZh = summaryZh,
        observedDataZh = observedDataZh,
        expectedBaselineZh = expectedBaselineZh,
        recommendationZh = if (detected) recommendationZh else CLEAN_RECOMMENDATION_ZH,
        rawEvidence = rawEvidence.toSortedMap(),
        sourceAttribution = sourceAttribution,
    )
}

internal fun Map<String, String>.getTrimmed(key: String): String = this[key]?.trim().orEmpty()
