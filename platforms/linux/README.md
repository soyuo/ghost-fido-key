# Linux UHID access and packaging

The authenticator uses Linux `/dev/uhid`. The Debian package installs
`udev/70-ghost-fido-key.rules` at `/usr/lib/udev/rules.d/` so systemd-logind's
`uaccess` tag grants access to the active local seat user. The rule does not
make the device world-writable and the desktop app does not need to run as
root. Debian install, upgrade, and removal hooks reload udev rules and retrigger
the UHID rule when `udevadm` is available.

If the package hook reports that udev could not be refreshed, or if the package
was installed in an environment without `udevadm`, reload rules manually and
reconnect the session or reboot:

```sh
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=misc --sysname-match=uhid
```

If `/dev/uhid` is not created or access is still denied, check that the kernel
UHID module is available and that the user session is managed by logind. The
runtime reports permission and device errors instead of elevating itself.

AppImage and other non-Debian formats do not install system udev rules. From
the repository root on Ubuntu, install the rule manually with:

```sh
sudo install -m 0644 platforms/linux/udev/70-ghost-fido-key.rules \
  /etc/udev/rules.d/70-ghost-fido-key.rules
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=misc --sysname-match=uhid
```

Other Linux distributions remain outside the supported matrix until
separately verified.
