// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.sdk

/**
 * 扫描开关。关掉的维度不会出现「假装检查过」的正常项，报告里会标成未启用。
 *
 * @property sensorSampleTimeoutMs 加速度采样等待时间。设为 0 可跳过采样。
 * @property includeRecentInput 是否把最近一次实时输入里已经命中的信号并进本次报告。
 */
data class VirtProbeConfig(
    val enableEmulator: Boolean = true,
    val enableContainer: Boolean = true,
    val enableVirtualDisplay: Boolean = true,
    val enableConsistency: Boolean = true,
    val enableInput: Boolean = true,
    val enableRuntime: Boolean = true,
    val sensorSampleTimeoutMs: Long = 200,
    val includeRecentInput: Boolean = true,
)
