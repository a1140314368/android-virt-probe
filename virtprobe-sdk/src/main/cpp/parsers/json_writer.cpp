// SPDX-License-Identifier: Apache-2.0
#include "parsers/json_writer.h"

#include <cstdio>
#include <vector>

namespace virtprobe {

void JsonWriter::beginObject() {
    beforeValue();
    out_ += '{';
    nested_.push_back(false);
}

void JsonWriter::endObject() {
    nested_.pop_back();
    out_ += '}';
}

void JsonWriter::beginArray() {
    beforeValue();
    out_ += '[';
    nested_.push_back(false);
}

void JsonWriter::endArray() {
    nested_.pop_back();
    out_ += ']';
}

void JsonWriter::key(const std::string& name) {
    if (!nested_.empty() && nested_.back()) {
        out_ += ',';
    }
    if (!nested_.empty()) {
        nested_.back() = true;
    }
    out_ += '"';
    out_ += jsonEscape(name);
    out_ += "\":";
    after_key_ = true;
}

void JsonWriter::value(const std::string& text) {
    beforeValue();
    out_ += '"';
    out_ += jsonEscape(text);
    out_ += '"';
}

void JsonWriter::value(int number) { value(static_cast<long long>(number)); }

void JsonWriter::value(long long number) {
    beforeValue();
    out_ += std::to_string(number);
}

void JsonWriter::value(bool bit) {
    beforeValue();
    out_ += bit ? "true" : "false";
}

void JsonWriter::beforeValue() {
    if (after_key_) {
        after_key_ = false;
        return;
    }
    if (!nested_.empty() && nested_.back()) {
        out_ += ',';
    }
    if (!nested_.empty()) {
        nested_.back() = true;
    }
}

std::string jsonEscape(const std::string& text) {
    std::string out;
    out.reserve(text.size() + 8);
    for (unsigned char c : text) {
        switch (c) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    return out;
}

}  // namespace virtprobe
