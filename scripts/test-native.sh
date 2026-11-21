#!/usr/bin/env bash
# 在没有 Android NDK 的 Linux 上编译并运行原生解析器自测。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CPP="$ROOT/virtprobe-sdk/src/main/cpp"
OUT="${TMPDIR:-/tmp}/virtprobe-parser-selftest"
CXX="${CXX:-g++}"
"$CXX" -std=c++17 -Wall -Wextra -Werror -I "$CPP" \
  "$CPP/parsers/text_parsers.cpp" \
  "$CPP/parsers/json_writer.cpp" \
  "$CPP/collectors/syscall_probe.cpp" \
  "$CPP/collectors/property_collector.cpp" \
  "$CPP/collectors/evidence_collector.cpp" \
  "$CPP/host/parser_selftest.cpp" \
  -o "$OUT"
"$OUT"
