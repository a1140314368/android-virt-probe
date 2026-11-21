// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <string>
#include <vector>

namespace virtprobe {

// 只负责把采集结果打成 UTF-8 JSON。非法控制字符会转义，避免 JNI 收到裸的 NUL。
class JsonWriter {
public:
    void beginObject();
    void endObject();
    void beginArray();
    void endArray();
    void key(const std::string& name);
    void value(const std::string& text);
    void value(int number);
    void value(long long number);
    void value(bool bit);
    const std::string& str() const { return out_; }

private:
    void beforeValue();
    std::string out_;
    // 每一层是否已经写过元素。对象的 key 也算一个元素。
    std::vector<bool> nested_;
    bool after_key_ = false;
};

std::string jsonEscape(const std::string& text);

}  // namespace virtprobe
