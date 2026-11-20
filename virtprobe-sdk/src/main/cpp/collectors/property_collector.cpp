// SPDX-License-Identifier: Apache-2.0
#include "collectors/property_collector.h"

#if defined(__ANDROID__)
#include <sys/system_properties.h>
#endif

namespace virtprobe {

std::vector<std::string> watchedPropertyKeys() {
    return {
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
    };
}

std::string readSystemProperty(const std::string& key) {
#if defined(__ANDROID__)
    char buffer[PROP_VALUE_MAX];
    buffer[0] = '\0';
    __system_property_get(key.c_str(), buffer);
    return std::string(buffer);
#else
    (void)key;
    return std::string();
#endif
}

}  // namespace virtprobe
