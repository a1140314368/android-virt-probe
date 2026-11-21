// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <string>
#include <vector>

namespace virtprobe {

// 采集一份原生证据 JSON。权限失败写进 errors，不抛异常。
std::string collectEvidenceJson();

std::vector<std::string> emulatorProbePaths();

}  // namespace virtprobe
