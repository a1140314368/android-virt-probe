// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.core.model

/**
 * 五大检测维度。报告、评分和演示界面都按这个枚举分组，避免调用方各自发明分类名。
 *
 * @property titleZh 面向人读的完整中文名。
 */
enum class SignalCategory(val titleZh: String) {
    /** 模拟器、虚拟机、云手机与 ARM 转译层。 */
    EMULATOR("模拟器与虚拟机"),

    /** 应用内虚拟化容器、多开分身与宿主框架。 */
    CONTAINER("应用内虚拟容器"),

    /** 虚拟副屏、投屏、录屏与外部显示路由。 */
    VIRTUAL_DISPLAY("虚拟屏幕与投屏"),

    /** Java、原生属性与 /proc、/sys 之间的一致性。 */
    CONSISTENCY("硬件一致性"),

    /** 输入设备盘点、无障碍自动化与实时事件溯源。 */
    INPUT("输入来源"),
}

/**
 * 单条信号的严重级别。未命中的检查项会降为 [INFO]，避免「全部项目」视图里正常项也涂成红色。
 */
enum class Severity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    /** 徽章上的短中文。 */
    val labelZh: String
        get() = when (this) {
            INFO -> "信息"
            LOW -> "低"
            MEDIUM -> "中"
            HIGH -> "高"
            CRITICAL -> "严重"
        }

    fun atLeast(other: Severity): Boolean = ordinal >= other.ordinal
}

/**
 * 综合环境结论。它是多信号关联后的总判，不是任何单条规则的直接输出。
 *
 * @property labelZh 状态卡上的短标签。
 */
enum class EnvironmentVerdict(val labelZh: String) {
    /** 没有中高危命中，最多只有低敏提示。 */
    REAL_DEVICE("真机基线"),

    /** 有可疑信号，但还不足以单独定性为模拟器或容器。 */
    SUSPICIOUS("可疑"),

    /** 模拟器 / 虚拟机特征占主导。 */
    EMULATOR_OR_VM("模拟器或虚拟机"),

    /** 应用内虚拟化容器或多开分身特征占主导。 */
    VIRTUAL_CONTAINER("虚拟容器"),

    /** 多类高危信号同时出现，或模拟器与容器同时成立。 */
    VIRTUALIZED_ENVIRONMENT("虚拟化环境"),
}
