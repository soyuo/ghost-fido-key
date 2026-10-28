# macOS CoreHID boundary

The macOS implementation uses `HIDVirtualDevice` from CoreHID. Access to the
API requires the `com.apple.developer.hid.virtual.device` entitlement and a
code-signed build whose provisioning profile contains that capability.

The Swift file in this directory is a lifecycle scaffold. It does not claim a
working virtual device until the entitlement request, development signature,
distribution signature, and browser path have all been tested.

## Required lifecycle

- Create a virtual device with the FIDO Alliance `0xF1D0` / `0x01` descriptor
  and 64-byte input/output reports.
- Activate it with a delegate that handles host output reports and close/stop
  events.
- Dispatch authenticator input reports only while the device is active.
- Deactivate and release the device on detach, app shutdown, and crash-recovery
  cleanup.

## Release gates

- Request and receive the entitlement; a source `.entitlements` file alone is
  not evidence of approval.
- Build and sign Intel and Apple silicon variants, then notarize the actual
  distribution artifact.
- Verify HID enumeration, Chrome/Edge FIDO discovery, registration, assertion,
  detach, and reinstall on each supported macOS version.

Until those gates pass, `MacOsCoreHidBackend` reports entitlement unavailable or
bridge not implemented and the application remains fail-closed.

## References

- [Apple HIDVirtualDevice](https://developer.apple.com/documentation/corehid/hidvirtualdevice)
- [Apple virtual HID entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.hid.virtual.device)
