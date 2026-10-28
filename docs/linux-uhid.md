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
- `detach` sends `UHID_DESTROY`; the backend also attempts cleanup during drop.
- Missing `/dev/uhid`, insufficient permissions, malformed events, and timeout
  are mapped to explicit shared capability or platform error states.

The adapter does not implement CTAPHID framing or CTAP commands. Those remain
owned by the common authenticator core and will consume complete reports through
the transport contract.

## Ubuntu LTS setup investigation

The runtime must not ask users to run the application as root. For each target
Ubuntu LTS release, record the distribution's `/dev/uhid` ownership, mode, and
ACL behavior, then provide the smallest package or udev rule that grants the
installed application access. Validate the rule from a fresh login and remove it
cleanly during uninstall.

Useful evidence commands on a Linux test host:

```sh
stat -c '%A %U %G %n' /dev/uhid
udevadm info --query=all --name=/dev/uhid
ls -l /dev/hidraw*
```

Do not mark Linux support complete from a Windows cross-build. The release gate
requires an Ubuntu LTS x64 and ARM64 device test, HID enumeration, CTAPHID
round-trip, and Chrome/Edge WebAuthn registration and assertion.

## References

- [Linux UHID kernel documentation](https://docs.kernel.org/hid/uhid.html)
- [FIDO CTAP HID descriptor and discovery](https://fidoalliance.org/specs/fido-v2.2-rd-20241003/fido-client-to-authenticator-protocol-v2.2-rd-20241003.pdf)
- [uhid-virt Rust wrapper](https://docs.rs/uhid-virt/latest/uhid_virt/)
