#!/usr/bin/env bash
# 可复现的环境对照。只使用 adb 的正常调试接口。
# 不执行 su，不改生产设备。调试附加会暂时让样本应用等待调试器，结束时 clear-debug-app。
set -euo pipefail
ADB="${ADB:-adb}"
PKG=io.virtprobe.sample
ACT=io.virtprobe.sample/.MainActivity
REPORT=/sdcard/Android/data/${PKG}/files/last-report.json

if [[ "${1:-}" == "debugger" ]]; then
  "$ADB" shell am force-stop "$PKG"
  "$ADB" shell rm -f "$REPORT"
  "$ADB" shell am start -D -n "$ACT"
  sleep 2
  PID="$("$ADB" shell pidof "$PKG" | tr -d '\r' | awk '{print $1}')"
  echo "pid=$PID"
  "$ADB" forward tcp:8700 "jdwp:$PID"
  # 保持 stdin 打开，jdb 才不会立刻断开。扫描发生在调试器已经接上之后。
  sleep 30 | jdb -attach localhost:8700 >/tmp/virtprobe-jdb.log 2>&1 &
  echo $! >/tmp/virtprobe-jdb.pid
  for _ in $(seq 1 30); do
    if "$ADB" shell ls "$REPORT" >/dev/null 2>&1; then
      break
    fi
    sleep 0.5
  done
  "$ADB" pull "$REPORT" /tmp/virtprobe-debugger-report.json
  echo "pulled /tmp/virtprobe-debugger-report.json"
  exit 0
fi

if [[ "${1:-}" == "debugger-off" ]]; then
  if [[ -f /tmp/virtprobe-jdb.pid ]]; then
    kill "$(cat /tmp/virtprobe-jdb.pid)" 2>/dev/null || true
    rm -f /tmp/virtprobe-jdb.pid
  fi
  "$ADB" forward --remove tcp:8700 >/dev/null 2>&1 || true
  "$ADB" shell am clear-debug-app
  "$ADB" shell am force-stop "$PKG"
  echo "debugger cleared"
  exit 0
fi

echo "usage: $0 debugger | debugger-off"
exit 2
