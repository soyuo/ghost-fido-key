# macOS CoreHID boundary

The macOS implementation uses `HIDVirtualDevice` from CoreHID. Access to the
API requires the `com.apple.developer.hid.virtual.device` entitlement and a
code-signed build whose provisioning profile contains that capability.

`GhostFidoVirtualDevice.swift` implements the CoreHID lifecycle, the FIDO report
descriptor, and a bounded output-report queue. `GhostFidoCoreHIDBridge.swift`
exports a narrow C ABI for readiness, activation, report I/O, and deactivation.
Swift Package Manager builds the bridge as a static library for the active Rust
target. It requires macOS 15.0 or later, explicitly configured product VID/PID
values, and a signed process entitlement.

## Required lifecycle

- Create a virtual device with the FIDO Alliance `0xF1D0` / `0x01` descriptor
  and 64-byte input/output reports. Vendor and product IDs must be assigned to
  this product.
- Activate it with a delegate that validates report type, ID, and length; keep
  at most 16 pending output reports and return explicit errors when full.
- Dispatch authenticator input reports only while the device is active and
  reject reports that are not exactly 64 bytes.
- Deactivate and release the device on detach and app shutdown. Rust owns the
  opaque bridge handle and drops it if the runtime exits unexpectedly.

## Release gates

- Request and receive the entitlement; a source `.entitlements` file alone is
  not evidence of approval.
- Build and sign Intel and Apple silicon variants, then notarize the actual
  distribution artifact.
- Verify HID enumeration, Chrome/Edge FIDO discovery, registration, assertion,
  detach, and reinstall on each supported macOS version.

The macOS workflow builds and links the bridge for x86_64 and arm64. The Rust
backend reports unavailable unless both assigned product IDs are provided at
build time and the running app's code signature contains the virtual HID
entitlement. A successful native build does not prove entitlement approval,
device enumeration, or browser interoperability.

## References

- [Apple HIDVirtualDevice](https://developer.apple.com/documentation/corehid/hidvirtualdevice)
- [Apple virtual HID entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.hid.virtual.device)
