// SPDX-License-Identifier: Apache-2.0
package io.virtprobe.core.catalog

/**
 * 公开资料中反复出现的模拟器、容器和自动化包名、路径与属性名。
 * 这里只保留判定用的特征常量。采集和判定逻辑都是本仓库独立编写的。
 */
object KnownSignals {
    val EMULATOR_PACKAGES: List<String> = listOf(
        "com.bluestacks",
        "com.bluestacks.appmart",
        "com.bignox.app",
        "com.bignox.app.store.hd",
        "com.bignox.google.installer",
        "com.vphone.launcher",
        "com.microvirt.launcher",
        "com.microvirt.launcher2",
        "com.microvirt.download",
        "com.microvirt.guide",
        "com.mumu.store",
        "com.netease.mumu.cloner",
        "com.genymotion.superuser",
        "com.google.android.launcher.layouts.genymotion",
        "com.ldmnq.launcher3",
        "com.ldmnq.android.pandora",
        "com.android.flysilkworm",
        "com.kop.zkop",
    )

    val CONTAINER_PACKAGES: List<String> = listOf(
        "com.lbe.parallel",
        "com.lbe.parallel.intl",
        "com.parallel.space.lite",
        "com.parallel.space.pro",
        "com.excelliance.dualaid",
        "com.excelliance.dualaid.vend",
        "com.ludashi.dualspace",
        "com.lody.virtual",
        "io.virtualapp",
        "io.va.exposed",
        "top.niunaijun.blackbox",
        "com.fvbox.lite",
        "com.vmos.pro",
        "com.vmos.app",
        "com.vmos.glb",
        "com.qihoo.magic",
        "com.qihoo.magic.xposed",
        "com.qihoo.magicmutiple",
        "com.dual.dualspace",
        "com.polestar.super.clone",
        "com.jiubang.commerce.gomultiple",
        "com.bly.dkplat",
        "info.red.virtual",
        "com.bfire.da.nui",
    )

    val AUTOMATION_PACKAGES: List<String> = listOf(
        "io.appium.settings",
        "io.appium.uiautomator2.server",
        "io.appium.uiautomator2.server.test",
        "com.github.uiautomator",
        "org.autojs.autojs",
        "org.autojs.autojspro",
        "com.stardust.scriptdroid",
        "net.dinglisch.android.taskerm",
        "com.arlosoft.macrodroid",
        "com.cyjh.mobileanjian",
        "com.cyjh.gundam",
        "com.touchsprite.android",
        "com.buzbuz.smartautoclicker",
    )

    val HOST_FRAMEWORK_PREFIXES: List<String> = listOf(
        "com.lody.virtual.",
        "io.virtualapp.",
        "com.excelliance.",
        "com.lbe.parallel.",
        "io.va.exposed.",
        "top.niunaijun.blackbox.",
        "com.qihoo.magic.",
        "de.robv.android.xposed.",
        "org.lsposed.",
    )

    val CONTAINER_LIBRARIES: List<String> = listOf(
        "libva++.so",
        "libv++.so",
        "libsandhook",
        "libepic.so",
        "libblackbox",
        "libvirtualapp",
    )

    val TRANSLATION_LIBRARIES: List<String> = listOf(
        "libhoudini.so",
        "libndk_translation.so",
        "libnb.so",
    )

    /**
     * 模拟器管道、套接字、驱动和厂商残留路径。
     * Java `File.exists` 与原生 `faccessat` 都应探测这份清单，再取并集。
     */
    val EMULATOR_PATHS: List<String> = listOf(
        "/dev/qemu_pipe",
        "/dev/goldfish_pipe",
        "/dev/socket/qemud",
        "/dev/socket/genyd",
        "/dev/socket/baseband_genyd",
        "/dev/vboxguest",
        "/dev/vboxuser",
        "/sys/qemu_trace",
        "/system/lib/libc_malloc_debug_qemu.so",
        "/system/lib64/libc_malloc_debug_qemu.so",
        "/system/bin/qemu-props",
        "/system/bin/qemud",
        "/sys/module/goldfish_audio",
        "/sys/module/goldfish_sync",
        "/fstab.nox",
        "/init.nox.rc",
        "/system/bin/nox-prop",
        "/system/lib/libnoxd.so",
        "/system/bin/ldinit",
        "/system/lib/libldutils.so",
        "/system/bin/microvirtd",
        "/system/bin/memud",
        "/mnt/windows/BstSharedFolder",
        "/sdcard/windows/BstSharedFolder",
    )

    val CRITICAL_EMULATOR_PATHS: Set<String> = setOf(
        "/dev/qemu_pipe",
        "/dev/goldfish_pipe",
        "/dev/socket/qemud",
        "/sys/qemu_trace",
        "/dev/vboxguest",
        "/dev/vboxuser",
    )

    /** 原生层默认读取的系统属性。与 `property_keys.h` 保持同一组键。 */
    val WATCHED_PROPERTIES: List<String> = listOf(
        "ro.kernel.qemu",
        "ro.boot.qemu",
        "ro.boot.qemu.avd_name",
        "ro.kernel.qemu.gles",
        "ro.kernel.android.qemud",
        "qemu.hw.mainkeys",
        "ro.hardware",
        "ro.boot.hardware",
        "ro.hardware.egl",
        "ro.hardware.gralloc",
        "ro.product.board",
        "ro.product.brand",
        "ro.product.manufacturer",
        "ro.product.model",
        "ro.product.device",
        "ro.product.name",
        "ro.product.cpu.abi",
        "ro.product.cpu.abilist",
        "ro.product.cpu.abi2",
        "ro.build.characteristics",
        "ro.build.fingerprint",
        "ro.build.flavor",
        "ro.build.tags",
        "ro.build.type",
        "ro.build.display.id",
        "ro.build.host",
        "ro.build.user",
        "ro.system.build.fingerprint",
        "ro.vendor.build.fingerprint",
        "ro.odm.build.fingerprint",
        "ro.bootimage.build.fingerprint",
        "ro.product.system.brand",
        "ro.product.vendor.brand",
        "ro.product.system.model",
        "ro.product.vendor.model",
        "init.svc.qemu-props",
        "init.svc.qemud",
        "init.svc.goldfish-logcat",
        "init.svc.goldfish-setup",
        "init.svc.vbox86-setup",
        "ro.boot.verifiedbootstate",
        "ro.boot.flash.locked",
        "ro.boot.vbmeta.device_state",
        "ro.dalvik.vm.native.bridge",
        "ro.enable.native.bridge.exec",
        "ro.dalvik.vm.isa.arm",
        "ro.dalvik.vm.isa.arm64",
        "persist.sys.nativebridge",
        "ro.arch",
        "ro.secure",
        "ro.debuggable",
        "ro.bootloader",
        "ro.serialno",
        "ro.boot.serialno",
        "gsm.version.ril-impl",
    )

    val INPUT_NAME_MARKERS: List<String> = listOf(
        "uinput",
        "goldfish",
        "ranchu",
        "virtio",
        "scrcpy",
        "vtouch",
        "vbox",
        "genymotion",
        "bluestacks",
        "memu",
        "nox",
        "ldplayer",
        "remote-desktop",
        "inputinjector",
        "qwerty",
    )

    val DISPLAY_NAME_MARKERS: List<String> = listOf(
        "scrcpy",
        "virtualdisplay",
        "virtual_display",
        "virtual display",
        "overlay",
        "miracast",
        "wifi-display",
        "wifi display",
        "wifidisplay",
        "chromecast",
        "screenrecord",
        "cast",
    )

    val GL_RENDERER_MARKERS: List<String> = listOf(
        "swiftshader",
        "llvmpipe",
        "virgl",
        "android emulator",
        "bluestacks",
        "memu",
        "nox",
        "virtualbox",
        "vbox",
        "gallium",
    )

    val IDENTITY_MARKERS: List<String> = listOf(
        "goldfish",
        "ranchu",
        "vbox86",
        "vbox",
        "genymotion",
        "bluestacks",
        "sdk_gphone",
        "google_sdk",
        "generic_x86",
        "generic/sdk",
        "android sdk built for",
        "emulator",
        "nox",
        "ldplayer",
        "memu",
        "microvirt",
        "cuttlefish",
        "crosvm",
        "cutf_cvm",
        "ttvm",
        "droid4x",
        "windroye",
        "andy",
    )

    val HARDWARE_EQUALS: Set<String> = setOf(
        "goldfish",
        "ranchu",
        "vbox86",
        "vbox86p",
        "nox",
        "ttvm_x86",
        "android_x86",
        "cutf",
        "cutf_cvm",
        "crosvm",
        "vexpress",
    )

    val QEMU_SERVICE_KEYS: List<String> = listOf(
        "init.svc.qemu-props",
        "init.svc.qemud",
        "init.svc.goldfish-logcat",
        "init.svc.goldfish-setup",
        "init.svc.vbox86-setup",
    )

    val SENSOR_MARKERS: List<String> = listOf("goldfish", "ranchu", "emulator", "virtual")

    val CLOUD_MARKERS: List<String> = listOf(
        "redfinger",
        "duoduoyun",
        "huaweicloud",
        "alicloud",
        "cloudphone",
        "primeos",
    )
}

object Attribution {
    const val EMULATOR: String =
        "方法参考 lotty520/Detect-Any、WsttXm/RiskEngine、strazzere/anti-emulator、brunovsiqueira/vigil-android、lamster2018/EasyProtector、framgia/android-emulator-detector（Apache-2.0 或 MIT）。本实现为独立编写，未复制上游源码。"

    const val CONTAINER: String =
        "方法参考 EasyProtector、vigil-android、RiskEngine、Detect-Any、su-vikas/conbeerlib（Apache-2.0 或 MIT）以及 Android 多用户、类加载与 procfs 的公开原理。本实现为独立编写，未复制上游源码。"

    const val DISPLAY: String =
        "基于 Android 公开 SDK（DisplayManager、AppOpsManager、MediaRouter、Activity.ScreenCaptureCallback）洁净室实现。虚拟屏分类思路参考 Detect-Any，未复制其源码。未使用 Huai-Tian/ScreenshotDetector（GPL-3.0）的任何代码。"

    const val CONSISTENCY: String =
        "跨层比对思路参考 RiskEngine 与 Detect-Any。指纹格式、CPU 核数、ABI/uname、电池与 Android Keystore 硬件背书均为依据公开接口独立实现，未复制上游源码。"

    const val INPUT: String =
        "输入设备盘点、无障碍/自动化框架与触控运动学为本仓库针对公开生态空白的独立实现，只使用 InputDevice、AccessibilityManager、MotionEvent、KeyEvent 以及 /proc 与 /dev 公开接口。未复制 1193776794/launch 与 ysrc/AntiVirtualApp（二者均无明确 SPDX 许可证）的源码。"
}
