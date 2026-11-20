// SPDX-License-Identifier: Apache-2.0
#include "collectors/evidence_collector.h"

#include "collectors/property_collector.h"
#include "collectors/syscall_probe.h"
#include "parsers/json_writer.h"
#include "parsers/text_parsers.h"

#include <utility>

namespace virtprobe {
namespace {

void writeStringArray(JsonWriter& json, const std::vector<std::string>& values) {
    json.beginArray();
    for (const auto& value : values) json.value(value);
    json.endArray();
}

}  // namespace

std::vector<std::string> emulatorProbePaths() {
    return {
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
        "/dev/uinput",
    };
}

std::string collectEvidenceJson() {
    const auto cpuinfo = readFileAt("/proc/cpuinfo", 32 * 1024);
    const auto maps = readFileAt("/proc/self/maps", 48 * 1024);
    const auto mountinfo = readFileAt("/proc/self/mountinfo", 48 * 1024);
    const auto cmdline = readFileAt("/proc/self/cmdline", 4 * 1024);
    const auto environ = readFileAt("/proc/self/environ", 16 * 1024);
    const auto input = readFileAt("/proc/bus/input/devices", 32 * 1024);
    const auto present = readFileAt("/sys/devices/system/cpu/present", 256);
    const auto temp = readFileAt("/sys/class/power_supply/battery/temp", 64);
    const auto voltage = readFileAt("/sys/class/power_supply/battery/voltage_now", 64);
    const auto capacity = readFileAt("/sys/class/power_supply/battery/capacity", 64);

    const auto cpuFacts = parseCpuInfo(cpuinfo.text);
    const auto presentFacts = parseCpuPresent(present.text);
    const auto mapEntries = parseMaps(maps.text);
    const auto mapHits = suspiciousMapPaths(mapEntries);
    const auto inputEntries = parseInputDevices(input.text);
    const auto inputHits = suspiciousInputNames(inputEntries);
    const auto battery = parseBatterySysfs(temp.text, voltage.text, capacity.text);

    std::vector<std::string> existing;
    std::vector<std::pair<std::string, std::string>> pathErrors;
    for (const auto& path : emulatorProbePaths()) {
        const std::string state = accessState(path);
        if (state == "PRESENT" && path != "/dev/uinput") {
            existing.push_back(path);
        } else if (state != "ABSENT" && state != "PRESENT") {
            pathErrors.emplace_back(path, state);
        }
    }

    std::vector<std::string> eventNodes;
    for (int index = 0; index < 16; ++index) {
        const std::string path = "/dev/input/event" + std::to_string(index);
        if (accessState(path) == "PRESENT") eventNodes.push_back(path);
    }

    JsonWriter json;
    json.beginObject();
    json.key("properties");
    json.beginObject();
    for (const auto& key : watchedPropertyKeys()) {
        json.key(key);
        json.value(readSystemProperty(key));
    }
    json.endObject();

    json.key("existingPaths");
    writeStringArray(json, existing);
    json.key("pathErrors");
    json.beginObject();
    for (const auto& item : pathErrors) {
        json.key(item.first);
        json.value(item.second);
    }
    json.endObject();

    json.key("cpuinfo");
    json.value(cpuinfo.text);
    json.key("cpuinfoError");
    json.value(cpuinfo.error);
    json.key("maps");
    json.value(maps.text);
    json.key("mapsError");
    json.value(maps.error);
    json.key("mountinfo");
    json.value(mountinfo.text);
    json.key("mountinfoError");
    json.value(mountinfo.error);
    json.key("cmdline");
    json.value(cmdline.text);
    json.key("cmdlineError");
    json.value(cmdline.error);
    json.key("environ");
    json.value(environ.text);
    json.key("environError");
    json.value(environ.error);
    json.key("inputDevices");
    json.value(input.text);
    json.key("inputError");
    json.value(input.error);
    json.key("cpuPresent");
    json.value(present.text);
    json.key("cpuPresentError");
    json.value(present.error);
    json.key("unameMachine");
    json.value(unameField('m'));
    json.key("unameSysname");
    json.value(unameField('s'));
    json.key("unameRelease");
    json.value(unameField('r'));
    json.key("uinput");
    json.value(accessState("/dev/uinput"));
    json.key("eventNodes");
    writeStringArray(json, eventNodes);
    json.key("batteryTemp");
    json.value(temp.text);
    json.key("batteryVoltage");
    json.value(voltage.text);
    json.key("batteryCapacity");
    json.value(capacity.text);

    json.key("hints");
    json.beginObject();
    json.key("cpu.processors");
    json.value(cpuFacts.processorCount);
    json.key("cpu.hypervisor");
    json.value(cpuFacts.hypervisor ? "1" : "0");
    json.key("cpu.presentCount");
    json.value(presentFacts.ok ? std::to_string(presentFacts.count) : "");
    json.key("maps.suspicious");
    json.value(static_cast<int>(mapHits.size()));
    json.key("input.suspicious");
    json.value(static_cast<int>(inputHits.size()));
    json.key("battery.tempOk");
    json.value(battery.tempOk ? "1" : "0");
    json.key("battery.voltageMicro");
    json.value(battery.voltageOk ? std::to_string(battery.voltageMicro) : "");
    json.endObject();
    json.endObject();
    return json.str();
}

}  // namespace virtprobe
