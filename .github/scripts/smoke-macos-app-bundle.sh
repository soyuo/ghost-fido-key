#!/usr/bin/env bash
set -Eeuo pipefail

app_path=${1:?Usage: smoke-macos-app-bundle.sh <app.bundle> [disk-image.dmg]}
dmg_path=${2:-}
expected_identifier=com.ghostfido.desktop

if [[ ! -d "$app_path" ]]; then
  echo "macOS app bundle is missing: $app_path" >&2
  exit 1
fi

temp_root=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/ghost-fido-macos-smoke.XXXXXX")
mount_point="$temp_root/dmg"
ordinary_copy="$temp_root/Applications/Ghost FIDO Key.app"
dmg_copy="$temp_root/DMG Applications/Ghost FIDO Key.app"
mounted=false
mkdir -p "$mount_point" "$(dirname "$ordinary_copy")" "$(dirname "$dmg_copy")"

cleanup() {
  local status=$?
  trap - EXIT
  if [[ "$mounted" == true ]]; then
    if ! hdiutil detach "$mount_point" -quiet; then
      echo "Failed to detach temporary macOS disk image: $mount_point" >&2
      status=1
    fi
  fi
  if ! rm -rf "$temp_root"; then
    echo "Failed to remove temporary macOS smoke-check directory: $temp_root" >&2
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT

verify_app() {
  local bundle=$1
  local identifier executable
  local plist="$bundle/Contents/Info.plist"
  if [[ ! -s "$plist" ]]; then
    echo "App bundle is missing Info.plist: $plist" >&2
    return 1
  fi
  identifier=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$plist")
  if [[ "$identifier" != "$expected_identifier" ]]; then
    echo "Unexpected app bundle identifier in $plist: $identifier" >&2
    return 1
  fi
  executable=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$plist")
  if [[ ! -x "$bundle/Contents/MacOS/$executable" ]]; then
    echo "App bundle executable is missing or not executable: $bundle/Contents/MacOS/$executable" >&2
    return 1
  fi
}

verify_app "$app_path"
echo "Copying app bundle into a temporary Applications directory."
ditto "$app_path" "$ordinary_copy"
verify_app "$ordinary_copy"
rm -rf "$ordinary_copy"
if [[ -e "$ordinary_copy" ]]; then
  echo "Temporary installed app bundle remains after removal: $ordinary_copy" >&2
  exit 1
fi

if [[ -n "$dmg_path" ]]; then
  if [[ ! -s "$dmg_path" ]]; then
    echo "macOS disk image is missing or empty: $dmg_path" >&2
    exit 1
  fi
  echo "Mounting macOS disk image: $dmg_path"
  hdiutil attach "$dmg_path" -nobrowse -readonly -mountpoint "$mount_point" -quiet
  mounted=true
  image_app=$(find "$mount_point" -type d -name '*.app' -prune -print -quit)
  if [[ -z "$image_app" ]]; then
    echo "No app bundle was found in mounted disk image: $dmg_path" >&2
    exit 1
  fi
  verify_app "$image_app"
  echo "Copying app bundle from mounted disk image."
  ditto "$image_app" "$dmg_copy"
  verify_app "$dmg_copy"
  hdiutil detach "$mount_point" -quiet
  mounted=false
  rm -rf "$dmg_copy"
  if [[ -e "$dmg_copy" ]]; then
    echo "Temporary DMG-installed app bundle remains after removal: $dmg_copy" >&2
    exit 1
  fi
fi

echo "macOS app bundle install/remove smoke check passed."
