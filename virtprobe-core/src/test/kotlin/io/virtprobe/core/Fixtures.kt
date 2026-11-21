// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.core

import io.virtprobe.core.catalog.KnownSignals
import io.virtprobe.core.model.AccelSample
import io.virtprobe.core.model.BatteryReading
import io.virtprobe.core.model.ConsistencySnapshot
import io.virtprobe.core.model.ContainerSnapshot
import io.virtprobe.core.model.DisplayFact
import io.virtprobe.core.model.EmulatorSnapshot
import io.virtprobe.core.model.InputAuditSnapshot
import io.virtprobe.core.model.InputDeviceFact
import io.virtprobe.core.model.InputSourceBits
import io.virtprobe.core.model.KeystoreSnapshot
import io.virtprobe.core.model.NodeVisibility
import io.virtprobe.core.model.ProbeSnapshots
import io.virtprobe.core.model.SensorFact
import io.virtprobe.core.model.VirtualDisplaySnapshot

internal const val SAMPLE_PKG = "io.virtprobe.sample"
internal const val PIXEL_FINGERPRINT =
    "google/shiba/shiba:14/UQ1A.240205.002/11224170:user/release-keys"

internal fun fingerSamples(): List<AccelSample> = listOf(
    AccelSample(0.12f, 0.20f, 9.70f),
    AccelSample(0.28f, -0.11f, 9.92f),
    AccelSample(-0.05f, 0.36f, 9.48f),
    AccelSample(-0.22f, 0.08f, 10.12f),
    AccelSample(0.18f, -0.27f, 9.61f),
    AccelSample(0.07f, 0.15f, 9.86f),
    AccelSample(0.21f, 0.02f, 9.73f),
    AccelSample(-0.09f, 0.19f, 10.04f),
)

internal fun realBuild(): Map<String, String> = mapOf(
    "BRAND" to "google",
    "MANUFACTURER" to "Google",
    "MODEL" to "Pixel 8",
    "DEVICE" to "shiba",
    "PRODUCT" to "shiba",
    "HARDWARE" to "shiba",
    "BOARD" to "shiba",
    "FINGERPRINT" to PIXEL_FINGERPRINT,
)

internal fun realProperties(): Map<String, String> = mapOf(
    "ro.product.brand" to "google",
    "ro.product.manufacturer" to "Google",
    "ro.product.model" to "Pixel 8",
    "ro.product.device" to "shiba",
    "ro.product.name" to "shiba",
    "ro.hardware" to "shiba",
    "ro.product.board" to "shiba",
    "ro.build.fingerprint" to PIXEL_FINGERPRINT,
    "ro.system.build.fingerprint" to PIXEL_FINGERPRINT,
    "ro.vendor.build.fingerprint" to PIXEL_FINGERPRINT,
    "ro.odm.build.fingerprint" to PIXEL_FINGERPRINT,
    "ro.build.characteristics" to "nosdcard",
    "ro.kernel.qemu" to "0",
    "ro.boot.qemu" to "",
    "ro.boot.verifiedbootstate" to "green",
    "ro.boot.flash.locked" to "1",
    "ro.boot.vbmeta.device_state" to "locked",
    "ro.product.cpu.abi" to "arm64-v8a",
    "ro.hardware.egl" to "adreno",
)

internal fun realCpuInfo(): String = """
    processor : 0
    BogoMIPS : 38.40
    Features : fp asimd aes pmull sha1 sha2 crc32
    CPU implementer : 0x41
    CPU architecture : 8
    CPU variant : 0x1
    CPU part : 0xd81
    CPU revision : 0

    processor : 1
    BogoMIPS : 38.40
    Features : fp asimd aes pmull sha1 sha2 crc32
    CPU implementer : 0x41
    CPU architecture : 8
    CPU variant : 0x1
    CPU part : 0xd81
    CPU revision : 0
""".trimIndent()

internal fun realEmulatorSnapshot(): EmulatorSnapshot = EmulatorSnapshot(
    javaBuild = realBuild(),
    nativeProperties = realProperties(),
    propertyOrigin = "native",
    existingPaths = emptyList(),
    probedPaths = KnownSignals.EMULATOR_PATHS,
    glRenderer = "Adreno (TM) 750",
    glVendor = "Qualcomm",
    cpuInfo = realCpuInfo(),
    sensorNames = listOf("LSM6DSO Accelerometer", "LSM6DSO Gyroscope"),
    accelerometerSamples = fingerSamples(),
    batteryTemperatureTenthsC = 285,
    batteryVoltageMv = 4120,
    networkInterfaceNames = listOf("wlan0", "rmnet0", "lo"),
)

internal fun realContainerSnapshot(userId: Int = 0): ContainerSnapshot {
    val data = if (userId == 0) "/data/user/0/$SAMPLE_PKG" else "/data/user/$userId/$SAMPLE_PKG"
    return ContainerSnapshot(
        packageName = SAMPLE_PKG,
        dataDir = data,
        sourceDir = "/data/app/~~abc==/$SAMPLE_PKG-def==/base.apk",
        nativeLibraryDir = "/data/app/~~abc==/$SAMPLE_PKG-def==/lib/arm64",
        userId = userId,
        packagesForUid = listOf(SAMPLE_PKG),
        cmdline = SAMPLE_PKG,
        mapsText = "70a0000000-70a0001000 r-xp 00000000 fd:00 123 /data/app/~~abc==/$SAMPLE_PKG-def==/base.apk",
        mountInfoText = "36 1 253:6 / / rw,relatime - ext4 /dev/block/dm-6 rw",
        environText = "TMPDIR=/data/user/0/$SAMPLE_PKG/cache",
        classLoaderDexPaths = listOf("/data/app/~~abc==/$SAMPLE_PKG-def==/base.apk"),
        stackFrames = listOf("io.virtprobe.sdk.VirtProbe.scan", "io.virtprobe.sample.MainActivity.onCreate"),
    )
}

internal fun realDisplaySnapshot(): VirtualDisplaySnapshot = VirtualDisplaySnapshot(
    displays = listOf(
        DisplayFact(
            displayId = 0,
            name = "内置屏幕",
            flags = 0,
            widthPx = 1080,
            heightPx = 2400,
            densityDpi = 420,
            refreshHz = 120f,
            isDefault = true,
        ),
    ),
    screenCaptureNotified = false,
    projectMediaMode = "MODE_IGNORED",
    projectAudioMode = "MODE_IGNORED",
    wifiDisplayOn = false,
)

internal fun realConsistencySnapshot(): ConsistencySnapshot = ConsistencySnapshot(
    javaBuild = realBuild(),
    nativeProperties = realProperties(),
    javaProcCpuInfo = realCpuInfo(),
    nativeProcCpuInfo = realCpuInfo(),
    sysCpuPresent = "0-1",
    runtimeProcessors = 2,
    javaAbis = listOf("arm64-v8a", "armeabi-v7a"),
    unameMachine = "aarch64",
    sensors = listOf(
        SensorFact(type = 1, name = "LSM6DSO Accelerometer", vendor = "STMicro"),
        SensorFact(type = 4, name = "LSM6DSO Gyroscope", vendor = "STMicro"),
    ),
    accelerometerSamples = fingerSamples(),
    javaBattery = BatteryReading(285, 4120, 76),
    sysBattery = BatteryReading(287, 4090, 76),
    keystore = KeystoreSnapshot(
        available = true,
        insideSecureHardware = true,
        attestationPresent = true,
        attestationSecurityLevel = "TrustedEnvironment",
        verifiedBootState = "Verified",
        deviceLocked = true,
    ),
)

internal fun realInputSnapshot(): InputAuditSnapshot = InputAuditSnapshot(
    devices = listOf(
        InputDeviceFact(
            id = 3,
            name = "fts_ts",
            descriptor = "abcd",
            vendorId = 0x2808,
            productId = 0x1001,
            isVirtual = false,
            isExternal = false,
            sources = InputSourceBits.SOURCE_TOUCHSCREEN,
        ),
    ),
    procBusInputText = """
        I: Bus=0018 Vendor=2808 Product=1001 Version=0100
        N: Name="fts_ts"
        H: Handlers=event2

    """.trimIndent(),
    uinputVisibility = NodeVisibility.ABSENT,
    inputEventNodes = listOf("/dev/input/event2"),
    instrumentationClassName = "android.app.Instrumentation",
)

internal fun realRuntimeSnapshot(): io.virtprobe.core.model.RuntimeSnapshot =
    io.virtprobe.core.model.RuntimeSnapshot(
        binaryProbes = mapOf(
            "/system/bin/su" to io.virtprobe.core.model.ProbeVisibility.NOT_VISIBLE,
            "/system/xbin/su" to io.virtprobe.core.model.ProbeVisibility.NOT_VISIBLE,
        ),
        mountState = io.virtprobe.core.model.ProbeVisibility.NOT_VISIBLE,
        mapsState = io.virtprobe.core.model.ProbeVisibility.NOT_VISIBLE,
        tracerPid = 0,
        javaDebuggerConnected = false,
        selinuxEnforce = "1",
        securityPatch = "2026-08-01",
        buildTags = "release-keys",
        roSecure = "1",
        roDebuggable = "0",
        adbEnabled = false,
        vpnActive = false,
        httpProxy = "",
        nowEpochMs = 1_763_600_000_000,
    )

internal fun realSnapshots(): ProbeSnapshots = ProbeSnapshots(
    emulator = realEmulatorSnapshot(),
    container = realContainerSnapshot(),
    virtualDisplay = realDisplaySnapshot(),
    consistency = realConsistencySnapshot(),
    input = realInputSnapshot(),
    runtime = realRuntimeSnapshot(),
)
