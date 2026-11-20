// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <string>
#include <vector>

namespace virtprobe {

struct FileRead {
    std::string text;
    std::string error;
    bool ok = false;
};

// 直接使用 openat / faccessat / uname。这些系统调用在 Linux 宿主机上也可编译，
// Android 与桌面 Linux 的差异只留在属性读取。
FileRead readFileAt(const std::string& path, std::size_t maxBytes);
std::string accessState(const std::string& path);
std::string unameField(char which);

}  // namespace virtprobe
