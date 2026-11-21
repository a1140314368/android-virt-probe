// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.core.model

/**
 * 加速度计样本，单位与 Android 传感器一致，为米/秒²。
 * 规则层只看数值，不依赖 SensorEvent。
 */
data class AccelSample(val x: Float, val y: Float, val z: Float)

/**
 * 模拟器与虚拟机维度的原始材料。属性值由采集层填入，规则层不主动读系统。
 *
 * @property javaBuild `Build.*` 字段，键用 BRAND、MODEL、FINGERPRINT 这类大写名。
 * @property nativeProperties 原生 `__system_property_get` 读到的系统属性。JNI 不可用时采集层会注明降级来源。
 * @property propertyOrigin 属性来源说明，例如 `native` 或 `java-reflection-fallback`。
 * @property existingPaths 确认存在的可疑路径。
 * @property probedPaths 本次实际探测过的路径，用来在未命中时说明「查过哪些」。
 * @property pathErrors 路径探测时的权限或 IO 错误。权限被拒绝不算命中。
 */
data class EmulatorSnapshot(
    val javaBuild: Map<String, String> = emptyMap(),
    val nativeProperties: Map<String, String> = emptyMap(),
    val propertyOrigin: String = "unspecified",
    val existingPaths: List<String> = emptyList(),
    val probedPaths: List<String> = emptyList(),
    val pathErrors: Map<String, String> = emptyMap(),
    val installedPackages: List<String> = emptyList(),
    val glRenderer: String = "",
    val glVendor: String = "",
    val glError: String = "",
    val cpuInfo: String = "",
    val mapsText: String = "",
    val sensorNames: List<String> = emptyList(),
    val accelerometerSamples: List<AccelSample> = emptyList(),
    val batteryTemperatureTenthsC: Int? = null,
    val batteryVoltageMv: Int? = null,
    val networkInterfaceNames: List<String> = emptyList(),
    val nativeHints: Map<String, String> = emptyMap(),
)

/**
 * 容器与多开维度的原始材料。路径均使用采集时的绝对路径。
 *
 * @property userId `uid / 100000`。工作资料（Work profile）也会是非 0 用户，单独出现只作为低敏提示。
 */
data class ContainerSnapshot(
    val packageName: String,
    val dataDir: String,
    val sourceDir: String,
    val nativeLibraryDir: String,
    val userId: Int,
    val packagesForUid: List<String> = emptyList(),
    val cmdline: String = "",
    val mapsText: String = "",
    val mountInfoText: String = "",
    val environText: String = "",
    val classLoaderDexPaths: List<String> = emptyList(),
    val stackFrames: List<String> = emptyList(),
    val readErrors: Map<String, String> = emptyMap(),
)

/**
 * 一块显示器的公开属性快照。flags 使用与 Android `Display` 相同的位定义，见 [DisplayFlagBits]。
 */
data class DisplayFact(
    val displayId: Int,
    val name: String,
    val flags: Int,
    val widthPx: Int,
    val heightPx: Int,
    val densityDpi: Int,
    val refreshHz: Float,
    val isDefault: Boolean,
)

/**
 * 虚拟屏幕与投屏维度的原始材料。
 *
 * @property screenCaptureNotified Android 14（API 34）`Activity.ScreenCaptureCallback` 是否已回调。
 * `null` 表示本次没有注册或平台未提供该回调，不能反推「没有人在录屏」。
 * @property projectMediaMode / [projectAudioMode] 本应用自己的 AppOp 模式，不是全系统录屏状态。
 */
data class VirtualDisplaySnapshot(
    val displays: List<DisplayFact> = emptyList(),
    val screenCaptureNotified: Boolean? = null,
    val projectMediaMode: String? = null,
    val projectAudioMode: String? = null,
    val remoteRouteNames: List<String> = emptyList(),
    val selectedRemoteRoute: String? = null,
    val wifiDisplayOn: Boolean? = null,
)

/** 与 Android `Display` 公开标志位保持一致的常量，方便 JVM 测试不依赖 SDK。 */
object DisplayFlagBits {
    const val FLAG_SUPPORTS_PROTECTED_BUFFERS: Int = 1 shl 0
    const val FLAG_SECURE: Int = 1 shl 1
    const val FLAG_PRIVATE: Int = 1 shl 2
    const val FLAG_PRESENTATION: Int = 1 shl 3
    const val FLAG_ROUND: Int = 1 shl 4
}

/**
 * 电池读数。温度单位是 0.1 摄氏度（与 `BatteryManager.EXTRA_TEMPERATURE` 一致），电压单位是毫伏。
 */
data class BatteryReading(
    val temperatureTenthsC: Int? = null,
    val voltageMv: Int? = null,
    val capacityPercent: Int? = null,
)

/** 传感器类型使用 Android `Sensor.TYPE_*` 的整型值。 */
data class SensorFact(
    val type: Int,
    val name: String,
    val vendor: String = "",
)

/**
 * Android Keystore / TEE（可信执行环境）硬件背书的解析结果。
 * 采集失败时 [available] 为 false，并在 [error] 写明原因，规则不会据此假装命中。
 *
 * @property attestationSecurityLevel `Software`、`TrustedEnvironment`、`StrongBox` 或解析失败时的说明。
 * @property verifiedBootState `Verified`、`SelfSigned`、`Unverified`、`Failed`。
 */
data class KeystoreSnapshot(
    val available: Boolean,
    val insideSecureHardware: Boolean? = null,
    val attestationPresent: Boolean = false,
    val attestationSecurityLevel: String? = null,
    val verifiedBootState: String? = null,
    val deviceLocked: Boolean? = null,
    val error: String? = null,
)

/**
 * 一致性维度的原始材料。Java 层、原生层和 proc/sys 层分开放，方便逐项对账。
 */
data class ConsistencySnapshot(
    val javaBuild: Map<String, String> = emptyMap(),
    val nativeProperties: Map<String, String> = emptyMap(),
    val javaProcCpuInfo: String = "",
    val nativeProcCpuInfo: String = "",
    val sysCpuPresent: String = "",
    val runtimeProcessors: Int = 0,
    val javaAbis: List<String> = emptyList(),
    val unameMachine: String = "",
    val sensors: List<SensorFact> = emptyList(),
    val accelerometerSamples: List<AccelSample> = emptyList(),
    val javaBattery: BatteryReading? = null,
    val sysBattery: BatteryReading? = null,
    val keystore: KeystoreSnapshot? = null,
    val readErrors: Map<String, String> = emptyMap(),
)

/** 与 Android `InputDevice` 源类型位相同的常量。 */
object InputSourceBits {
    const val SOURCE_UNKNOWN: Int = 0
    const val SOURCE_KEYBOARD: Int = 0x00000101
    const val SOURCE_DPAD: Int = 0x00000201
    const val SOURCE_TOUCHSCREEN: Int = 0x00001002
    const val SOURCE_MOUSE: Int = 0x00002002
    const val SOURCE_STYLUS: Int = 0x00004002
    const val SOURCE_ANY: Int = -0x100
}

/** 与 Android `MotionEvent` / `KeyEvent` 标志位相同的常量。 */
object InputEventBits {
    const val ACTION_DOWN: Int = 0
    const val ACTION_UP: Int = 1
    const val ACTION_MOVE: Int = 2
    const val ACTION_MASK: Int = 0xff

    const val FLAG_WINDOW_IS_OBSCURED: Int = 0x1
    const val FLAG_WINDOW_IS_PARTIALLY_OBSCURED: Int = 0x2

    /**
     * 无障碍服务改写或生成的事件标志。平台字段名是 `FLAG_IS_ACCESSIBILITY_EVENT`，值固定为 `0x800`。
     * 部分资料把它称为 accessibility-generated 标志，语义相同：事件由无障碍服务产生或改写。
     */
    const val FLAG_IS_ACCESSIBILITY_EVENT: Int = 0x800

    const val TOOL_TYPE_UNKNOWN: Int = 0
    const val TOOL_TYPE_FINGER: Int = 1
    const val TOOL_TYPE_STYLUS: Int = 2
    const val TOOL_TYPE_MOUSE: Int = 3

    /** Android `KeyCharacterMap.VIRTUAL_KEYBOARD`。 */
    const val DEVICE_ID_VIRTUAL_KEYBOARD: Int = -1
}

/** 节点可见性。权限不足必须单独记录，不能当成「节点不存在」或「攻击成功」。 */
enum class NodeVisibility {
    PRESENT,
    ABSENT,
    PERMISSION_DENIED,
    UNKNOWN,
}

/** 静态输入设备。 */
data class InputDeviceFact(
    val id: Int,
    val name: String,
    val descriptor: String = "",
    val vendorId: Int = 0,
    val productId: Int = 0,
    val isVirtual: Boolean = false,
    val isExternal: Boolean = false,
    val sources: Int = 0,
)

/** 一次触控采样，字段与 MotionEvent 对齐，但不引用 Android 类型。 */
data class MotionSample(
    val action: Int,
    val deviceId: Int,
    val source: Int,
    val toolType: Int,
    val flags: Int,
    val pressure: Float,
    val size: Float,
    val touchMajor: Float,
    val x: Float,
    val y: Float,
    val eventTime: Long,
    val downTime: Long,
    val isDeviceVirtual: Boolean? = null,
    val deviceName: String? = null,
)

/** 一次按键采样。 */
data class KeySample(
    val keyCode: Int,
    val action: Int,
    val deviceId: Int,
    val source: Int,
    val flags: Int,
    val eventTime: Long,
    val downTime: Long,
    val isDeviceVirtual: Boolean? = null,
    val deviceName: String? = null,
)

/**
 * 输入维度的静态审计材料。实时事件不放在这里，而由 [io.virtprobe.core.input.InputEventAnalyzer] 单独分析。
 */
data class InputAuditSnapshot(
    val devices: List<InputDeviceFact> = emptyList(),
    val procBusInputText: String? = null,
    val procBusReadError: String? = null,
    val uinputVisibility: NodeVisibility = NodeVisibility.UNKNOWN,
    val inputEventNodes: List<String> = emptyList(),
    val inputNodeError: String? = null,
    val enabledAccessibilityServices: List<String> = emptyList(),
    val installedAutomationPackages: List<String> = emptyList(),
    val runningProcessNames: List<String> = emptyList(),
    val instrumentationClassName: String? = null,
)

/**
 * 交给 [io.virtprobe.core.engine.ProbeEngine] 的一次完整材料。某个维度为 null 表示本次未启用。
 *
 * @property liveInputFindings 实时输入监控已经产出的命中项，会并入同一份报告。
 */
/** 路径探测结果。看不到不等于不存在。 */
enum class ProbeVisibility {
    PRESENT,
    NOT_VISIBLE,
    DENIED,
}

/**
 * 运行环境材料：提权、注入、调试、SELinux、补丁和网络姿态。
 * 不包含本应用签名、安装来源或 DEX 自校验。
 */
data class RuntimeSnapshot(
    val binaryProbes: Map<String, ProbeVisibility> = emptyMap(),
    val mountHits: List<String> = emptyList(),
    val mountState: ProbeVisibility = ProbeVisibility.NOT_VISIBLE,
    val mapHits: List<String> = emptyList(),
    val mapsState: ProbeVisibility = ProbeVisibility.NOT_VISIBLE,
    val tracerPid: Int? = null,
    val javaDebuggerConnected: Boolean? = null,
    val selinuxEnforce: String? = null,
    val securityPatch: String = "",
    val buildTags: String = "",
    val roSecure: String = "",
    val roDebuggable: String = "",
    val adbEnabled: Boolean? = null,
    val vpnActive: Boolean? = null,
    val httpProxy: String? = null,
    val cluePackages: List<String> = emptyList(),
    val nowEpochMs: Long = 0L,
)

data class ProbeSnapshots(
    val emulator: EmulatorSnapshot? = null,
    val container: ContainerSnapshot? = null,
    val virtualDisplay: VirtualDisplaySnapshot? = null,
    val consistency: ConsistencySnapshot? = null,
    val input: InputAuditSnapshot? = null,
    val runtime: RuntimeSnapshot? = null,
    val liveInputFindings: List<SignalFinding> = emptyList(),
)

/**
 * 实时输入的人读结论。演示页的触控区直接绑定这四个中文字段。
 */
data class InputNarrative(
    val suspicious: Boolean,
    val verdictZh: String,
    val observedDataZh: String,
    val expectedBaselineZh: String,
    val recommendationZh: String,
    val findings: List<SignalFinding>,
)
