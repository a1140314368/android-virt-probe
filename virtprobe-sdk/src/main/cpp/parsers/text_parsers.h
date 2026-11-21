// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <string>
#include <vector>

namespace virtprobe {

struct CpuInfoFacts {
    int processorCount = 0;
    bool hypervisor = false;
};

struct CpuPresentFacts {
    bool ok = false;
    int count = 0;
};

struct MapEntry {
    std::string perms;
    std::string path;
};

struct MountEntry {
    std::string mountPoint;
    std::string fstype;
    std::string source;
};

struct InputDevFact {
    std::string name;
    int vendor = -1;
    int product = -1;
    std::string handlers;
};

struct BatteryFacts {
    bool tempOk = false;
    int tempTenths = 0;
    bool voltageOk = false;
    long long voltageMicro = 0;
    bool capacityOk = false;
    int capacity = 0;
};

// 这些解析器和 virtprobe-core 的 ProcText 对齐。判定仍以 Kotlin 为准，这里给原生证据做预整理。
CpuInfoFacts parseCpuInfo(const std::string& text);
CpuPresentFacts parseCpuPresent(const std::string& text);
std::vector<MapEntry> parseMaps(const std::string& text);
std::vector<MountEntry> parseMountInfo(const std::string& text);
std::vector<InputDevFact> parseInputDevices(const std::string& text);
BatteryFacts parseBatterySysfs(const std::string& temp, const std::string& voltageNow, const std::string& capacity);

std::vector<std::string> suspiciousMapPaths(const std::vector<MapEntry>& maps);
std::vector<std::string> suspiciousInputNames(const std::vector<InputDevFact>& devices);

}  // namespace virtprobe
