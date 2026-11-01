#!/usr/bin/env bash
set -Eeuo pipefail

package_path=${1:?Usage: smoke-linux-deb-package.sh <package.deb>}
if [[ ! -s "$package_path" ]]; then
  echo "Debian package is missing or empty: $package_path" >&2
  exit 1
fi

package_name=$(dpkg-deb --field "$package_path" Package)
if [[ -z "$package_name" ]]; then
  echo "Could not read the Debian package name: $package_path" >&2
  exit 1
fi

application_path=/usr/bin/ghost-fido-desktop
udev_rule_path=/usr/lib/udev/rules.d/70-ghost-fido-key.rules
udev_rule_pattern='SUBSYSTEM=="misc", KERNEL=="uhid", TAG+="uaccess"'

if dpkg-query --show --showformat='${db:Status-Status}' "$package_name" 2>/dev/null | grep -Fxq installed; then
  echo "Expected a clean runner, but $package_name is already installed." >&2
  exit 1
fi

cleanup() {
  trap - EXIT
  local status
  status=$(dpkg-query --show --showformat='${db:Status-Status}' "$package_name" 2>/dev/null || true)
  if [[ -n "$status" && "$status" != not-installed ]]; then
    echo "Cleaning up the Debian package after an incomplete smoke check." >&2
    if ! dpkg --purge "$package_name"; then
      echo "Failed to purge $package_name from the ephemeral runner." >&2
      exit 1
    fi
  fi
}
trap cleanup EXIT

echo "Installing $package_name from $package_path."
dpkg --install "$package_path"

status=$(dpkg-query --show --showformat='${db:Status-Status}' "$package_name")
if [[ "$status" != installed ]]; then
  echo "Expected $package_name to be installed; dpkg reports: $status" >&2
  exit 1
fi
if [[ ! -x "$application_path" ]]; then
  echo "Installed desktop executable is missing: $application_path" >&2
  exit 1
fi
if [[ ! -s "$udev_rule_path" ]] || ! grep -Fqx "$udev_rule_pattern" "$udev_rule_path"; then
  echo "Installed UHID udev rule is missing or does not grant only the uaccess tag: $udev_rule_path" >&2
  exit 1
fi
echo "Verified installed executable and UHID udev rule."

echo "Purging $package_name from the ephemeral runner."
dpkg --purge "$package_name"

status=$(dpkg-query --show --showformat='${db:Status-Status}' "$package_name" 2>/dev/null || true)
if [[ -n "$status" && "$status" != not-installed ]]; then
  echo "Package database still reports $package_name as $status after purge." >&2
  exit 1
fi
if [[ -e "$application_path" || -e "$udev_rule_path" ]]; then
  echo "Package-owned application or udev-rule file remains after purge." >&2
  exit 1
fi

echo "Linux Debian install/remove smoke check passed."
