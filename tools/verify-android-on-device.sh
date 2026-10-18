#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tools/verify-android-on-device.sh APK [ADB]

Installs a signed PQVPN preview APK on one explicitly authorized Android
device, launches it, and fails unless the expected activity stays alive and in
the foreground without producing an Android crash-buffer entry.

ADB defaults to the first adb in PATH. The test clears only Android's crash
log buffer immediately before launch. It does not read application data.
EOF
}

[[ $# -ge 1 && $# -le 2 ]] || { usage >&2; exit 64; }

apk="$1"
adb="${2:-$(command -v adb || true)}"
package="io.github.tadaka9.pqvpn"

[[ -f "$apk" ]] || { echo "APK not found: $apk" >&2; exit 66; }
[[ -n "$adb" && -x "$adb" ]] || {
  echo "adb not found; pass its path as the second argument." >&2
  exit 69
}

mapfile -t devices < <("$adb" devices | awk 'NR > 1 && $2 == "device" {print $1}')
[[ ${#devices[@]} -eq 1 ]] || {
  echo "Expected exactly one authorized Android device; found ${#devices[@]}." >&2
  "$adb" devices -l >&2
  exit 69
}

echo "Installing $(basename "$apk") on ${devices[0]}"
"$adb" install -r "$apk"
"$adb" shell pm list packages | grep -Fxq "package:$package" || {
  echo "Installed APK does not expose the expected package: $package" >&2
  exit 1
}

component="$("$adb" shell cmd package resolve-activity --brief "$package" | tail -n 1 | tr -d '\r')"
expected_component="$package/.PqvpnActivity"
[[ "$component" == "$expected_component" ]] || {
  echo "Unexpected or missing launcher activity: $component" >&2
  exit 1
}

"$adb" logcat -b crash -c
"$adb" shell am force-stop "$package"
"$adb" shell am start -W -n "$component"
sleep 8

pid="$("$adb" shell pidof "$package" | tr -d '\r')"
[[ -n "$pid" ]] || { echo "PQVPN exited during the launch hold." >&2; exit 1; }

crash="$("$adb" logcat -b crash -d -v brief)"
[[ -z "$crash" ]] || {
  echo "Android recorded a crash after launch:" >&2
  printf '%s\n' "$crash" >&2
  exit 1
}

"$adb" shell dumpsys activity activities \
  | grep -Eq "(topResumedActivity|mResumedActivity).*${package}" || {
    echo "PQVPN is alive but is not the resumed foreground activity." >&2
    exit 1
  }

echo "PASS: $package is foreground, PID $pid, with a clean crash buffer."
