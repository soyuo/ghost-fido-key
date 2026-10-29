#!/bin/sh
set -eu

if ! command -v udevadm >/dev/null 2>&1; then
    echo "Ghost FIDO Key: udevadm is unavailable; reload udev rules manually after installation or removal." >&2
    exit 0
fi

if ! udevadm control --reload-rules; then
    echo "Ghost FIDO Key: could not reload udev rules; run 'sudo udevadm control --reload-rules' manually." >&2
    exit 0
fi

if ! udevadm trigger --subsystem-match=misc --sysname-match=uhid; then
    echo "Ghost FIDO Key: could not retrigger the UHID rule; reconnect the session or reboot." >&2
fi
exit 0