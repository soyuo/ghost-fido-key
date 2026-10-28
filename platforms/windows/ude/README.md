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

The application must not claim `Available` from device enumeration alone. The
driver must be signed, installed, and answer the readiness handshake first.

## Build and signing gates

- Build x64 and native ARM64 configurations with a supported WDK and Visual
  Studio Desktop C++ workload.
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
