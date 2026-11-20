// SPDX-License-Identifier: Apache-2.0
// 宿主机自测：不链接 Android NDK，只验证解析器和 Linux syscall 采集能跑通。
#include "collectors/evidence_collector.h"
#include "collectors/property_collector.h"
#include "collectors/syscall_probe.h"
#include "parsers/text_parsers.h"

#include <iostream>
#include <string>

namespace {

bool definedAndroid() {
#if defined(__ANDROID__)
    return true;
#else
    return false;
#endif
}

}  // namespace

namespace {

int fail(const std::string& message) {
    std::cerr << "FAIL " << message << "\n";
    return 1;
}

}  // namespace

int main() {
    const auto present = virtprobe::parseCpuPresent("0-7");
    if (!present.ok || present.count != 8) return fail("cpu present 0-7");
    const auto split = virtprobe::parseCpuPresent("0-3,5,7");
    if (!split.ok || split.count != 6) return fail("cpu present split");
    if (virtprobe::parseCpuPresent("cpu").ok) return fail("cpu present garbage should fail");

    const auto cpu = virtprobe::parseCpuInfo("processor : 0\nflags : fpu hypervisor\nprocessor : 1\n");
    if (cpu.processorCount != 2 || !cpu.hypervisor) return fail("cpuinfo");

    const auto maps = virtprobe::parseMaps("aaaa-bbbb r-xp 00000000 fd:00 9 /data/app/other/libva++.so\n");
    if (maps.size() != 1 || maps[0].path != "/data/app/other/libva++.so") return fail("maps path");
    if (virtprobe::suspiciousMapPaths(maps).empty()) return fail("maps marker");

    const auto mounts = virtprobe::parseMountInfo("1 1 0:1 / /data/user/0/pkg rw - ext4 /dev/block/by-name/userdata rw\n");
    if (mounts.size() != 1 || mounts[0].mountPoint != "/data/user/0/pkg" || mounts[0].fstype != "ext4") {
        return fail("mountinfo");
    }

    const auto devices = virtprobe::parseInputDevices(
        "I: Bus=0006 Vendor=0000 Product=0001 Version=0000\nN: Name=\"goldfish_touch\"\nH: Handlers=event0\n");
    if (devices.size() != 1 || devices[0].name != "goldfish_touch" || devices[0].vendor != 0 || devices[0].product != 1) {
        return fail("input devices");
    }
    if (virtprobe::suspiciousInputNames(devices).empty()) return fail("input marker");

    const auto battery = virtprobe::parseBatterySysfs("0\n", "0\n", "50\n");
    if (!battery.tempOk || battery.tempTenths != 0 || !battery.voltageOk || battery.voltageMicro != 0 || battery.capacity != 50) {
        return fail("battery");
    }

    if (virtprobe::watchedPropertyKeys().empty()) return fail("property keys");
    bool sawQemu = false;
    for (const auto& key : virtprobe::watchedPropertyKeys()) {
        if (key == "ro.kernel.qemu") sawQemu = true;
    }
    if (!sawQemu) return fail("missing ro.kernel.qemu");
    if (!definedAndroid() && !virtprobe::readSystemProperty("ro.kernel.qemu").empty()) {
        return fail("host property should be empty");
    }

    const std::string json = virtprobe::collectEvidenceJson();
    if (json.empty() || json.front() != '{' || json.back() != '}') return fail("evidence json envelope");
    if (json.find("\"cpuinfo\"") == std::string::npos) return fail("evidence cpuinfo");
    if (json.find("\"unameMachine\"") == std::string::npos) return fail("evidence uname");
    if (json.find("ro.kernel.qemu") == std::string::npos) return fail("evidence properties");
    const auto liveCpu = virtprobe::readFileAt("/proc/cpuinfo", 4096);
    if (!liveCpu.ok || liveCpu.text.find("processor") == std::string::npos) return fail("live /proc/cpuinfo");
    const auto liveMaps = virtprobe::readFileAt("/proc/self/maps", 4096);
    if (!liveMaps.ok || liveMaps.text.empty()) return fail("live /proc/self/maps");

    std::cout << "virtprobe native selftest ok, evidenceBytes=" << json.size()
              << " uname=" << virtprobe::unameField('m') << "\n";
    return 0;
}
