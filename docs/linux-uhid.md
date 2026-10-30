# Linux UHID adapter

The Linux adapter uses the kernel userspace HID interface through `/dev/uhid`.
The adapter is compiled only on Linux and exposes the shared `VirtualHidBackend`
contract from `ghost-platform`.

## Runtime contract

- The report descriptor advertises FIDO Alliance usage page `0xF1D0`, CTAPHID
  usage `0x01`, and 64-byte input and output reports.
- `attach` sends `UHID_CREATE2` and waits for `UHID_START` before reporting an
  attached device.
- Input reports are accepted only when they are exactly 64 bytes.
- Output, open, close, stop, and feature-report events are handled explicitly.
- Each output-read call uses one monotonic timeout; unrelated UHID events do not
  restart the caller's deadline.
- `detach` sends `UHID_DESTROY`; the backend also attempts cleanup during drop.
- Missing `/dev/uhid`, insufficient permissions, malformed events, and timeout
  are mapped to explicit shared capability or platform error states.

The adapter does not implement CTAPHID framing or CTAP commands. Those remain
owned by the common authenticator core and will consume complete reports through
the transport contract.

## Active-session device access

The application must not run as root. The repository includes
[`70-ghost-fido-key.rules`](../platforms/linux/udev/70-ghost-fido-key.rules),
which tags only the `/dev/uhid` misc device with `uaccess`. On systemd-logind
systems this lets logind grant an ACL to the active local seat instead of
opening the device to every user. The rule does not change the device mode or
grant access to background/headless sessions.

For a development installation on Ubuntu LTS, an administrator can install and
reload a manual override with:

```sh
sudo install -m 0644 platforms/linux/udev/70-ghost-fido-key.rules \
  /etc/udev/rules.d/70-ghost-fido-key.rules
sudo udevadm control --reload-rules
sudo udevadm trigger --action=change --subsystem-match=misc --sysname-match=uhid
```

Start a fresh local desktop login before validating the ACL. Check the device
node and effective access from that session:

```sh
stat -c '%A %U %G %n' /dev/uhid
getfacl /dev/uhid
udevadm info --query=all --name=/dev/uhid
ls -l /dev/hidraw*
```

The Debian package installs the rule under `/usr/lib/udev/rules.d/` and runs its
udev refresh hook on install, upgrade, and removal. Package removal owns cleanup
of that packaged file; do not remove it manually. For AppImage, other
non-Debian formats, or a manual development override, remove the `/etc` rule
and refresh udev when uninstalling that setup:

```sh
sudo rm /etc/udev/rules.d/70-ghost-fido-key.rules
sudo udevadm control --reload-rules
sudo udevadm trigger --action=change --subsystem-match=misc --sysname-match=uhid
```

Ubuntu releases without systemd-logind seat ACL handling need a separately
reviewed access policy and must not silently fall back to world-writable
permissions. Real-host ownership, mode, ACL, fresh-login, and uninstall checks
are still required before claiming Linux runtime support.

Do not mark Linux support complete from a Windows cross-build. The release gate
requires an Ubuntu LTS x64 and ARM64 device test, HID enumeration, CTAPHID
round-trip, and Chrome/Edge WebAuthn registration and assertion.

## References

- [Linux UHID kernel documentation](https://docs.kernel.org/hid/uhid.html)
- [FIDO CTAP HID descriptor and discovery](https://fidoalliance.org/specs/fido-v2.2-rd-20241003/fido-client-to-authenticator-protocol-v2.2-rd-20241003.pdf)
- [uhid-virt Rust wrapper](https://docs.rs/uhid-virt/latest/uhid_virt/)
