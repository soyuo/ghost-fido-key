# macOS CoreHID boundary

The macOS implementation uses `HIDVirtualDevice` from CoreHID. Access to the
API requires the `com.apple.developer.hid.virtual.device` entitlement and a
code-signed build whose provisioning profile contains that capability.

`GhostFidoVirtualDevice.swift` implements the CoreHID lifecycle, the FIDO report
descriptor, and a bounded output-report queue. It requires macOS 15.0 or later
and explicit product VID/PID values. The Rust provider remains fail-closed; the
Swift actor is not yet wired into the app's Rust runtime or signed distribution.

## Required lifecycle

- Create a virtual device with the FIDO Alliance `0xF1D0` / `0x01` descriptor
  and 64-byte input/output reports. Vendor and product IDs must be assigned to
  this product.
- Activate it with a delegate that validates report type, ID, and length; keep
  at most 16 pending output reports and return explicit errors when full.
- Dispatch authenticator input reports only while the device is active and
  reject reports that are not exactly 64 bytes.
- Deactivate and release the device on detach and app shutdown. The Rust owner
  must still provide crash-recovery cleanup when the bridge is integrated.

## Release gates

- Request and receive the entitlement; a source `.entitlements` file alone is
  not evidence of approval.
- Build and sign Intel and Apple silicon variants, then notarize the actual
  distribution artifact.
- Verify HID enumeration, Chrome/Edge FIDO discovery, registration, assertion,
  detach, and reinstall on each supported macOS version.

The macOS workflow type-checks this source for x86_64 and arm64. Until the Rust
bridge, granted entitlement, signed runtime, assigned product identity, and
browser path are validated, `MacOsCoreHidBackend` reports unavailable and the
application remains fail-closed.

## References

- [Apple HIDVirtualDevice](https://developer.apple.com/documentation/corehid/hidvirtualdevice)
- [Apple virtual HID entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.hid.virtual.device)
