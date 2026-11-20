// SPDX-License-Identifier: Apache-2.0
#include "parsers/text_parsers.h"

#include <cctype>
#include <cstdlib>

namespace virtprobe {
namespace {

std::string lowerCopy(const std::string& text) {
    std::string out = text;
    for (char& ch : out) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return out;
}

std::string trim(const std::string& text) {
    std::size_t begin = 0;
    while (begin < text.size() && std::isspace(static_cast<unsigned char>(text[begin]))) {
        ++begin;
    }
    std::size_t end = text.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1]))) {
        --end;
    }
    return text.substr(begin, end - begin);
}

std::string unescapeMount(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\\' && i + 3 < text.size() && text[i + 1] == '0' && text[i + 2] == '4' && text[i + 3] == '0') {
            out.push_back(' ');
            i += 3;
        } else {
            out.push_back(text[i]);
        }
    }
    return out;
}

bool startsWith(const std::string& text, const char* prefix) {
    const std::string p(prefix);
    return text.size() >= p.size() && text.compare(0, p.size(), p) == 0;
}

std::string fieldAfter(const std::string& line, const char* key) {
    const std::string token(key);
    const auto pos = line.find(token);
    if (pos == std::string::npos) return "";
    const auto from = pos + token.size();
    const auto end = line.find(' ', from);
    return line.substr(from, end == std::string::npos ? std::string::npos : end - from);
}

bool parseIntStrict(const std::string& text, int& out) {
    if (text.empty()) return false;
    char* end = nullptr;
    const long value = std::strtol(text.c_str(), &end, 10);
    if (end == text.c_str() || *end != '\0') return false;
    out = static_cast<int>(value);
    return true;
}

}  // namespace

CpuInfoFacts parseCpuInfo(const std::string& text) {
    CpuInfoFacts facts;
    const std::string lower = lowerCopy(text);
    facts.hypervisor = lower.find("hypervisor") != std::string::npos || lower.find("qemu") != std::string::npos ||
                       lower.find("goldfish") != std::string::npos;
    std::size_t cursor = 0;
    while (cursor < text.size()) {
        const auto next = text.find('\n', cursor);
        const std::string line = trim(text.substr(cursor, next == std::string::npos ? std::string::npos : next - cursor));
        if (startsWith(line, "processor") && line.find(':') != std::string::npos) {
            ++facts.processorCount;
        }
        if (next == std::string::npos) break;
        cursor = next + 1;
    }
    return facts;
}

CpuPresentFacts parseCpuPresent(const std::string& text) {
    CpuPresentFacts facts;
    const std::string trimmed = trim(text);
    if (trimmed.empty()) return facts;
    int count = 0;
    std::size_t cursor = 0;
    while (cursor <= trimmed.size()) {
        const auto comma = trimmed.find(',', cursor);
        const std::string part = trim(trimmed.substr(cursor, comma == std::string::npos ? std::string::npos : comma - cursor));
        if (part.empty()) return CpuPresentFacts{};
        const auto dash = part.find('-');
        if (dash == std::string::npos) {
            int value = 0;
            if (!parseIntStrict(part, value) || value < 0) return CpuPresentFacts{};
            ++count;
        } else {
            int start = 0;
            int end = 0;
            if (!parseIntStrict(part.substr(0, dash), start) || !parseIntStrict(part.substr(dash + 1), end) || end < start) {
                return CpuPresentFacts{};
            }
            count += end - start + 1;
        }
        if (comma == std::string::npos) break;
        cursor = comma + 1;
    }
    facts.ok = count > 0;
    facts.count = count;
    return facts;
}

std::vector<MapEntry> parseMaps(const std::string& text) {
    std::vector<MapEntry> out;
    std::size_t cursor = 0;
    while (cursor < text.size()) {
        const auto next = text.find('\n', cursor);
        const std::string line = text.substr(cursor, next == std::string::npos ? std::string::npos : next - cursor);
        // start-end perms offset dev inode path
        const auto sep1 = line.find(' ');
        if (sep1 != std::string::npos && line.find('-') < sep1) {
            std::size_t i = sep1;
            while (i < line.size() && line[i] == ' ') ++i;
            const auto permEnd = line.find(' ', i);
            if (permEnd != std::string::npos) {
                MapEntry entry;
                entry.perms = line.substr(i, permEnd - i);
                int fields = 0;
                std::size_t pos = permEnd;
                while (pos < line.size() && fields < 3) {
                    while (pos < line.size() && line[pos] == ' ') ++pos;
                    if (pos >= line.size()) break;
                    const auto fieldEnd = line.find(' ', pos);
                    pos = fieldEnd == std::string::npos ? line.size() : fieldEnd;
                    ++fields;
                }
                while (pos < line.size() && line[pos] == ' ') ++pos;
                if (pos < line.size()) entry.path = line.substr(pos);
                if (!entry.perms.empty()) out.push_back(entry);
            }
        }
        if (next == std::string::npos) break;
        cursor = next + 1;
    }
    return out;
}

std::vector<MountEntry> parseMountInfo(const std::string& text) {
    std::vector<MountEntry> out;
    std::size_t cursor = 0;
    while (cursor < text.size()) {
        const auto next = text.find('\n', cursor);
        const std::string line = text.substr(cursor, next == std::string::npos ? std::string::npos : next - cursor);
        const auto sep = line.find(" - ");
        if (sep != std::string::npos) {
            const std::string left = line.substr(0, sep);
            const std::string right = line.substr(sep + 3);
            std::vector<std::string> leftFields;
            std::string current;
            for (char ch : left) {
                if (ch == ' ') {
                    if (!current.empty()) leftFields.push_back(current);
                    current.clear();
                } else {
                    current.push_back(ch);
                }
            }
            if (!current.empty()) leftFields.push_back(current);
            std::string fstype;
            std::string source;
            std::size_t i = 0;
            while (i < right.size() && right[i] == ' ') ++i;
            const auto sp1 = right.find(' ', i);
            if (sp1 != std::string::npos && leftFields.size() >= 5) {
                fstype = right.substr(i, sp1 - i);
                std::size_t j = sp1;
                while (j < right.size() && right[j] == ' ') ++j;
                const auto sp2 = right.find(' ', j);
                source = right.substr(j, sp2 == std::string::npos ? std::string::npos : sp2 - j);
                MountEntry entry;
                entry.mountPoint = unescapeMount(leftFields[4]);
                entry.fstype = fstype;
                entry.source = unescapeMount(source);
                out.push_back(entry);
            }
        }
        if (next == std::string::npos) break;
        cursor = next + 1;
    }
    return out;
}

std::vector<InputDevFact> parseInputDevices(const std::string& text) {
    std::vector<InputDevFact> out;
    InputDevFact current;
    bool any = false;
    auto flush = [&]() {
        if (!any) return;
        out.push_back(current);
        current = InputDevFact{};
        any = false;
    };
    std::size_t cursor = 0;
    while (cursor <= text.size()) {
        const auto next = text.find('\n', cursor);
        std::string line = text.substr(cursor, next == std::string::npos ? std::string::npos : next - cursor);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (trim(line).empty()) {
            flush();
        } else if (startsWith(line, "N: Name=")) {
            any = true;
            std::string name = line.substr(std::string("N: Name=").size());
            name = trim(name);
            if (name.size() >= 2 && name.front() == '"' && name.back() == '"') {
                name = name.substr(1, name.size() - 2);
            }
            current.name = name;
        } else if (startsWith(line, "I:")) {
            any = true;
            const std::string vendor = fieldAfter(line, "Vendor=");
            const std::string product = fieldAfter(line, "Product=");
            if (!vendor.empty()) current.vendor = static_cast<int>(std::strtol(vendor.c_str(), nullptr, 16));
            if (!product.empty()) current.product = static_cast<int>(std::strtol(product.c_str(), nullptr, 16));
        } else if (startsWith(line, "H: Handlers=")) {
            any = true;
            current.handlers = trim(line.substr(std::string("H: Handlers=").size()));
        }
        if (next == std::string::npos) break;
        cursor = next + 1;
    }
    flush();
    return out;
}

BatteryFacts parseBatterySysfs(const std::string& temp, const std::string& voltageNow, const std::string& capacity) {
    BatteryFacts facts;
    int tempValue = 0;
    if (parseIntStrict(trim(temp), tempValue)) {
        facts.tempOk = true;
        facts.tempTenths = tempValue;
    }
    int voltage = 0;
    if (parseIntStrict(trim(voltageNow), voltage)) {
        facts.voltageOk = true;
        facts.voltageMicro = voltage;
    }
    int cap = 0;
    if (parseIntStrict(trim(capacity), cap)) {
        facts.capacityOk = true;
        facts.capacity = cap;
    }
    return facts;
}

std::vector<std::string> suspiciousMapPaths(const std::vector<MapEntry>& maps) {
    const char* markers[] = {"libhoudini", "libndk_translation", "libva++", "libsandhook", "libblackbox", "libvirtualapp", "qemu", "goldfish"};
    std::vector<std::string> hits;
    for (const auto& entry : maps) {
        const std::string lower = lowerCopy(entry.path);
        for (const char* marker : markers) {
            if (!entry.path.empty() && lower.find(marker) != std::string::npos) {
                hits.push_back(entry.path);
                break;
            }
        }
    }
    return hits;
}

std::vector<std::string> suspiciousInputNames(const std::vector<InputDevFact>& devices) {
    const char* markers[] = {"uinput", "goldfish", "ranchu", "virtio", "scrcpy", "vtouch", "vbox", "genymotion", "bluestacks", "qwerty"};
    std::vector<std::string> hits;
    for (const auto& device : devices) {
        const std::string lower = lowerCopy(device.name);
        for (const char* marker : markers) {
            if (lower.find(marker) != std::string::npos) {
                hits.push_back(device.name);
                break;
            }
        }
    }
    return hits;
}

}  // namespace virtprobe
