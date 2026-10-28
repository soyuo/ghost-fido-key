# Windows UDE driver boundary

This directory reserves the native Windows implementation required by the
Rust `WindowsUdeBackend`. It is intentionally separate from the Rust workspace:
UDE is a KMDF/UdeCx kernel-driver surface and must be built with the Windows
Driver Kit (WDK).

## Required native lifecycle

1. `EvtDriverDeviceAdd` initializes the emulated host controller with UdeCx.
2. The client driver creates one virtual USB device and supplies a FIDO HID
   descriptor with 64-byte input and output endpoints.
3. Endpoint queues receive and complete URBs without blocking at the wrong IRQL.
4. The driver plugs the device in only after all descriptors and endpoint
   queues are ready, and plugs it out before removal.
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
- The current native driver does not implement the IOCTL handler, and the Rust
  adapter does not implement attach, detach, or report IO. A successful future
  handshake alone therefore cannot mark the backend `Available`.

The IOCTL grants read access only. The eventual control-device interface must
also apply an explicit device ACL and validate every operation in kernel mode;
the handshake is not an authorization boundary for report traffic.

## Build and signing gates

- Build-only KMDF project: `ghost-fido-ude.vcxproj`. It compiles `driver.c`
  for x64 and ARM64 with the pinned WDK 10.0.28000.2526 NuGet packages and
  writes `.sys` outputs under the repository `target/windows-ude` directory.
- The project and CI do not produce an INF, catalog, signed package, or release
  artifact. The compiled scaffold is not installable or functional.
- Test installation, elevation, reboot, upgrade, and removal on supported
  Windows versions.
- Sign the driver package using the distribution policy selected for the
  release. Test-signing is development evidence only.
- Verify Device Manager enumeration, HID report round-trip, Chrome/Edge FIDO
  discovery, registration, and assertion separately.

No driver binary is produced by this repository yet. Until these gates pass,
`WindowsUdeBackend` reports the boundary as unavailable and fails closed.

## References

- [Microsoft UDE overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/developing-windows-drivers-for-emulated-usb-host-controllers-and-devices)
- [Write a UDE client driver](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/writing-a-ude-client-driver)
- [Windows ARM driver requirements](https://learn.microsoft.com/en-us/windows/arm/faq)
