// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <string>
#include <vector>

namespace virtprobe {

// 与 virtprobe-core 的 KnownSignals.WATCHED_PROPERTIES 保持同一组键。
std::vector<std::string> watchedPropertyKeys();

// Android 上走 __system_property_get。其它系统返回空字符串，调用方据此标记降级。
std::string readSystemProperty(const std::string& key);

}  // namespace virtprobe
