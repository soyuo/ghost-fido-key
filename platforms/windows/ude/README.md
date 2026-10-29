# Windows UDE driver boundary

This directory contains the first native Windows implementation slice for the
Rust `WindowsUdeBackend`. It is intentionally separate from the Rust workspace:
UDE is a KMDF/UdeCx kernel-driver surface and must be built with the Windows
Driver Kit (WDK).

## Required native lifecycle

1. `EvtDriverDeviceAdd` initializes the KMDF device and registers the UDE host
   controller with UdeCx. The UdeCx USB-device capability callback currently
   reports optional USB controller capabilities as unsupported; this is
   separate from the driver's implemented FIDO transport capabilities in its
   user-mode status response.
2. When nonzero, explicitly assigned VID and PID build properties are present,
   the driver adds a USB 2.0 FIDO HID descriptor set and creates the UDE device.
   The default zero values leave the controller running without a virtual USB
   device.
3. On an explicit attach IOCTL, the driver creates the default control endpoint
   and both 64-byte interrupt endpoint objects, then plugs in the virtual
   device. The HID report descriptor and fixed-profile class requests are
   handled on EP0. Interrupt IN/OUT requests exchange 64-byte reports with
   bounded kernel queues.
4. Device context cleanup calls `UdecxUsbDevicePlugOutAndDelete` before freeing
   any unconsumed UDE initialization parameters.
5. A restricted user-mode control device exposes readiness, attach, detach, and
   report operations to the Rust application through versioned IOCTLs. URBs are
   completed from a separate DPC; pending interrupt-IN requests are held in a
   cancellable manual queue and purged during detach.

The status response reports the driver capabilities implemented in source:
the FIDO HID profile, attach/detach, and both report-I/O directions. These bits
describe the source-level driver contract; they do not prove that the driver is
installed, attached, or working on a target device. With a valid assigned
identity, all required capability bits, and exact report sizes, the Rust adapter
reports `Configured` and permits a runtime start attempt. Strict `Available`
status remains gated on runtime validation; configuration or a successful attach
does not prove report exchange or browser support.

## User-mode control protocol

`ghost_fido_ude_protocol.h` is the native ABI definition. The Rust adapter
mirrors its fixed-width little-endian fields in `windows_ude.rs`.

- `IOCTL_GHOST_FIDO_UDE_QUERY_STATUS` uses `FILE_DEVICE_UNKNOWN`, function
  `0x800`, `METHOD_BUFFERED`, and `FILE_READ_ACCESS`.
- The 16-byte request contains `Size`, protocol major/minor, and a zero reserved
  field. The current protocol is version 1.2.
- The 44-byte response starts with `Size`, signature `GFUD`, protocol
  major/minor, capability flags, input/output report sizes, two zero reserved
  fields, then the configured vendor and product IDs as 32-bit values. Rust
  rejects IDs outside the 16-bit USB range, zero, and `0xFFFF`. FIDO input and
  output reports must both be 64 bytes.
- Capability bits declare controller readiness, the FIDO HID profile, attach
  and detach operations, and report I/O. The current source advertises all
  four because these code paths are implemented. They describe driver
  capabilities, not runtime readiness or validated platform support.
- A client accepts the same major version and ignores trailing fields from a
  newer minor version after checking the declared response size. A different
  major version, truncated or oversized response, wrong signature, nonzero
  reserved fields, or mismatched report sizes is unavailable.
- Attach/detach and report IOCTLs use fixed-size versioned records. Input
  reports are exactly 64 bytes. Output report reads return immediately with
  `STATUS_NO_MORE_ENTRIES` when the bounded queue is empty; Rust polls until its
  caller-supplied timeout expires.
- The native driver exposes `\\.\GhostFidoUde` with read/write access for
  interactive users and full access for Local System and Administrators. The
  driver reports all four source-implemented capability bits. With a valid,
  assigned vendor/product identity and exact 64-byte report sizes, the Rust
  adapter reports `Configured` and permits a runtime start attempt. `Configured`
  does not mean the attach/report path has succeeded or that a browser can
  discover the device; the desktop continues to label runtime support
  unverified. Missing or invalid identity, status, or report sizes remain
  unavailable and prevent startup.

The IOCTL access bits and controller ACL both restrict access. Every operation
validates versions, exact structure sizes, reserved fields, and report lengths
in kernel mode; the readiness handshake is not an authorization boundary for
report traffic.

## Build and signing gates

- Build-only KMDF project: `ghost-fido-ude.vcxproj`. It compiles `driver.c`
  for x64 and ARM64 with the pinned WDK 10.0.28000.2526 NuGet packages and
  writes `.sys` outputs under the repository `target/windows-ude` directory.
- `GhostFidoUde.inf` registers the development controller against the
  project-owned `ROOT\GhostFidoUde` ID. `New-DriverPackages.ps1` stages that INF
  with the architecture-specific `.sys` and uses WDK `Inf2Cat` to create
  `target/windows-ude/packages/x64` and `target/windows-ude/packages/arm64`.
  Each directory contains its INF, SYS, and architecture-specific CAT. CI
  uploads these unsigned development packages for seven days. The catalog is
  unsigned metadata, not a driver signature or proof of installation/runtime
  compatibility. The package catalog targets Windows 11 24H2 and 25H2; this
  packaging check is not a declaration of validated OS support.
- Default builds set `GhostFidoVendorId` and `GhostFidoProductId` to zero, so
  no virtual USB device is created. To enable descriptor/device creation in a
  development build, pass both properties to MSBuild, for example
  `/p:GhostFidoVendorId=0x1234 /p:GhostFidoProductId=0x0001`. Replace these
  example values only with USB IDs assigned to the product. Do not use another
  vendor's IDs or claim a third-party identity. CI intentionally uses the zero
  defaults. The status response advertises all four source-implemented
  capability bits. The response exposes the configured IDs, but defaults both
  to zero, and Rust explicitly reports that a valid product-assigned VID/PID is
  required. Together, valid assigned identity, all required capability bits,
  and exact report sizes produce a `Configured` state that permits a runtime
  start attempt; this is not proof of operational transport readiness.
- The CI package is unsigned and is not ready for end-user installation or
  product use. Signing and release distribution remain separate gates.
- Test installation, elevation, reboot, upgrade, and removal on supported
  Windows versions.
- Sign the driver package using the distribution policy selected for the
  release. Test-signing is development evidence only.
- Verify Device Manager enumeration, HID report round-trip, Chrome/Edge FIDO
  discovery, registration, and assertion separately.

CI compiles x64 and ARM64 `.sys` files and stages unsigned INF/SYS/CAT packages
under the ignored `target/` directory. Those build outputs are not signed or
ready for general installation. The source implements the descriptor,
class-request, and report-transport paths. At runtime, valid assigned IDs and
the required readiness profile allow the desktop to attempt attaching the
configured backend. Successful attach still does not prove bidirectional
report exchange or browser discovery. Signed packaging, installation, runtime
round-trip, and Chrome/Edge WebAuthn continue to require direct validation;
until then, the platform remains unverified and is not declared supported.

## References

- [Microsoft UDE overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/developing-windows-drivers-for-emulated-usb-host-controllers-and-devices)
- [Write a UDE client driver](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/writing-a-ude-client-driver)
- [Windows ARM driver requirements](https://learn.microsoft.com/en-us/windows/arm/faq)
