// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.core.model

/**
 * 一条可解释的检测信号。
 *
 * 设计上每条信号都同时携带「给人看的三段说明」和「给程序对账的原始证据」：
 * 界面默认只展开三段中文，原始键值收进折叠区。
 *
 * @property signalId 稳定标识，例如 `emu.prop.qemu`。同一标识在一次报告里对应一组检查，而不是某一行日志。
 * @property category 所属的五大维度。
 * @property severity 命中时的严重级别。未命中时固定为 [Severity.INFO]。
 * @property confidence 「该异常成立」的置信度，范围 0.0 到 1.0。未命中时为 0。
 * @property detected 本次是否命中异常。`false` 表示已检查且符合真机基线。
 * @property titleZh 检测项标题。
 * @property summaryZh 一句话摘要。
 * @property observedDataZh 触发问题的数据是什么：写明实际读到的值。
 * @property expectedBaselineZh 正常真机应该是什么。
 * @property recommendationZh 建议怎么处理。未命中时说明无需处置。
 * @property rawEvidence 原始键值证据。只放短文本，长文件会在采集层截断。
 * @property sourceAttribution 方法来源与许可证说明。本仓库的判定代码都是独立编写的。
 */
data class SignalFinding(
    val signalId: String,
    val category: SignalCategory,
    val severity: Severity,
    val confidence: Double,
    val detected: Boolean,
    val titleZh: String,
    val summaryZh: String,
    val observedDataZh: String,
    val expectedBaselineZh: String,
    val recommendationZh: String,
    val rawEvidence: Map<String, String>,
    val sourceAttribution: String,
)
