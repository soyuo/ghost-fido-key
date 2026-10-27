# Ghost FIDO Key

Cross-platform software FIDO2 authenticator scaffold. The intended shared
implementation language is Rust, with a Tauri desktop UI planned and a native
virtual-HID adapter per operating system.

## Current status

This repository contains only the initial Rust workspace and platform boundary.
It does not yet implement CTAP, credentials, cryptography, persistence, a GUI,
or virtual HID drivers. The current platform backend deliberately reports
unavailable and fails closed.

## Workspace layout

- `apps/ghost-fido`: development entry point.
- `crates/ghost-fido-core`: platform-independent product and protocol domain.
- `crates/ghost-platform`: OS boundary for future virtual HID adapters.
- `resources/`: design notes and implementation plan.

## Build and run

Install the Rust stable toolchain, then run:

```sh
cargo run -p ghost-fido
```

This command only prints scaffold status. A successful build does not indicate
that a virtual security key is available.

## Planned platform adapters

- Linux: evaluate the UHID userspace interface and its device permissions.
- Windows: implement and package a native virtual USB/HID driver.
- macOS: validate the supported virtual HID mechanism and required Apple
  entitlements before committing to distribution.

Each adapter must be implemented and validated on its target operating system.
