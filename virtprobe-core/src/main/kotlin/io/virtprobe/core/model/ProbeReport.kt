// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.core.model

/**
 * 一个维度在本次扫描中的汇总，供首屏五个状态卡直接绑定。
 *
 * @property enabled 该维度是否参与本次扫描。
 * @property checkedCount 该维度产出的检查项数量，含未命中项。
 * @property anomalyCount 命中的异常项数量（含低敏）。
 * @property mediumOrAboveCount 中危及以上命中数，用来决定状态卡配色。
 * @property highestSeverity 命中项里的最高级别；没有命中时为 [Severity.INFO]。
 * @property statusZh `未启用` / `正常` / `低敏提示 N 项` / `命中 N 项异常`。
 */
data class ModuleSummary(
    val category: SignalCategory,
    val enabled: Boolean,
    val checkedCount: Int,
    val anomalyCount: Int,
    val mediumOrAboveCount: Int,
    val highestSeverity: Severity,
    val statusZh: String,
)

/**
 * 一次扫描的完整报告。
 *
 * @property schemaVersion 报告结构版本，当前为 1。
 * @property reportId 本次报告标识，形如 `vp-<epochMillis>`。
 * @property generatedAtEpochMs 报告生成时间，Unix 毫秒。
 * @property verdict 关联引擎给出的总判。
 * @property riskScore 0 到 100 的综合风险分。只累计命中项，并在多维度同时命中时加分。
 * @property riskBandZh 风险分的中文档位：低 / 中 / 高 / 严重。
 * @property conclusionTitleZh 一句话核心结论，供首屏大标题使用。
 * @property conclusionSummaryZh 一两句说明命中了哪些维度，以及总体建议。
 * @property checkCount 全部检查项数量。
 * @property anomalyCount 命中异常项数量。
 * @property findings 全部检查项。未命中的项也保留，方便「全部项目」视图对照基线。
 * @property moduleSummaries 五个维度的汇总，顺序与 [SignalCategory] 一致。
 * @property scoreBreakdownZh 评分怎么来的，给人看的简短说明。
 */
data class ProbeReport(
    val schemaVersion: Int,
    val reportId: String,
    val generatedAtEpochMs: Long,
    val verdict: EnvironmentVerdict,
    val riskScore: Int,
    val riskBandZh: String,
    val conclusionTitleZh: String,
    val conclusionSummaryZh: String,
    val checkCount: Int,
    val anomalyCount: Int,
    val findings: List<SignalFinding>,
    val moduleSummaries: List<ModuleSummary>,
    val scoreBreakdownZh: String,
) {
    /** 格式化的 JSON 文本，使用两个空格缩进。 */
    fun toPrettyJson(): String = io.virtprobe.core.json.ReportJson.stringify(this)
}
