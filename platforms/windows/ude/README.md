# Windows UDE driver boundary

This directory contains the first native Windows implementation slice for the
Rust `WindowsUdeBackend`. It is intentionally separate from the Rust workspace:
UDE is a KMDF/UdeCx kernel-driver surface and must be built with the Windows
Driver Kit (WDK).

## Required native lifecycle

1. `EvtDriverDeviceAdd` initializes the KMDF device and registers the UDE host
   controller with UdeCx. The controller capability callback currently reports
   capabilities as unsupported.
2. When nonzero, explicitly assigned VID and PID build properties are present,
   the driver adds a USB 2.0 FIDO HID descriptor set and creates the UDE device.
   The default zero values leave the controller running without a virtual USB
   device.
3. The driver creates the default control endpoint and both 64-byte interrupt
   endpoint objects before plugging in the virtual device. Endpoint requests
   currently complete with `STATUS_NOT_SUPPORTED`; HID class requests and FIDO
   report transport are not implemented.
4. Device context cleanup calls `UdecxUsbDevicePlugOutAndDelete` before freeing
   any unconsumed UDE initialization parameters.
5. A restricted user-mode control device exposes readiness, attach, detach, and
   report operations to the Rust application through versioned IOCTLs.

The application must not claim `Available` from device enumeration or an open
control handle alone. The driver must answer the versioned status IOCTL with
the expected protocol signature, report sizes, and capability bits. The Rust
adapter still reports the backend as unavailable until its attach, detach, and
report operations are implemented end to end.

## User-mode control protocol

`ghost_fido_ude_protocol.h` is the native ABI definition. The Rust adapter
mirrors its fixed-width little-endian fields in `windows_ude.rs`.

- `IOCTL_GHOST_FIDO_UDE_QUERY_STATUS` uses `FILE_DEVICE_UNKNOWN`, function
  `0x800`, `METHOD_BUFFERED`, and `FILE_READ_ACCESS`.
- The 16-byte request contains `Size`, protocol major/minor, and a zero reserved
  field. The current request is version 1.0.
- The 36-byte response starts with `Size`, signature `GFUD`, protocol
  major/minor, capability flags, input/output report sizes, and two zero
  reserved fields. FIDO input and output reports must both be 64 bytes.
- Capability bits declare controller readiness, the FIDO HID profile, attach
  and detach operations, and report I/O. A driver must advertise all four for
  the complete runtime contract.
- A client accepts the same major version and ignores trailing fields from a
  newer minor version after checking the declared response size. A different
  major version, truncated or oversized response, wrong signature, nonzero
  reserved fields, or mismatched report sizes is unavailable.
- The native driver exposes `\\.\GhostFidoUde` with a read-only status ACL. It
  reports only `CONTROLLER_READY`; FIDO profile, attach/detach, and report I/O
  remain unimplemented even when the virtual device has been plugged in. The
  Rust adapter requires all four capabilities and also lacks attach, detach,
  and report operations, so this handshake cannot mark the backend `Available`.

The IOCTL grants read access only. The controller device ACL allows status reads
and grants full access only to Local System and Administrators. Every future
operation must validate its inputs in kernel mode; the handshake is not an
authorization boundary for report traffic.

## Build and signing gates

- Build-only KMDF project: `ghost-fido-ude.vcxproj`. It compiles `driver.c`
  for x64 and ARM64 with the pinned WDK 10.0.28000.2526 NuGet packages and
  writes `.sys` outputs under the repository `target/windows-ude` directory.
- Default builds set `GhostFidoVendorId` and `GhostFidoProductId` to zero, so
  no virtual USB device is created. To enable descriptor/device creation in a
  development build, pass both properties to MSBuild, for example
  `/p:GhostFidoVendorId=0x1234 /p:GhostFidoProductId=0x0001`. Replace these
  example values only with USB IDs assigned to the product. Do not use another
  vendor's IDs or claim a third-party identity. CI intentionally uses the zero
  defaults. The current driver does not implement HID class requests or FIDO
  traffic, and these properties do not authorize product identity or confer
  readiness.
- The project and CI do not produce an INF, catalog, signed package, or release
  artifact. The compiled scaffold is not installable or functional.
- Test installation, elevation, reboot, upgrade, and removal on supported
  Windows versions.
- Sign the driver package using the distribution policy selected for the
  release. Test-signing is development evidence only.
- Verify Device Manager enumeration, HID report round-trip, Chrome/Edge FIDO
  discovery, registration, and assertion separately.

CI compiles x64 and ARM64 `.sys` files under the ignored `target/` directory.
Those build outputs are not installable driver packages. Until virtual-device
enumeration, endpoint I/O, the control protocol, signing, and installation are
implemented and validated, `WindowsUdeBackend` reports unavailable and fails
closed.

## References

- [Microsoft UDE overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/developing-windows-drivers-for-emulated-usb-host-controllers-and-devices)
- [Write a UDE client driver](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/writing-a-ude-client-driver)
- [Windows ARM driver requirements](https://learn.microsoft.com/en-us/windows/arm/faq)
