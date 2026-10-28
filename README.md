# Ghost FIDO Key

Cross-platform software FIDO2 authenticator scaffold. The shared application
backend is Rust, with a Tauri 2 desktop shell using React and TypeScript. A
native virtual-HID adapter is required for each supported operating system.

## Current status

This repository contains the initial Rust workspace, platform boundary, and
desktop UI scaffold. It does not yet implement CTAP, credentials, cryptography,
persistence, or virtual HID drivers. The current platform backend deliberately
reports unavailable and fails closed.

## Workspace layout

- `apps/ghost-fido`: development entry point.
- `apps/desktop`: Tauri 2 desktop shell and React/TypeScript UI.
- `crates/ghost-fido-core`: platform-independent product and protocol domain.
- `crates/ghost-platform`: OS boundary for future virtual HID adapters.
- `resources/`: design notes and implementation plan.

## Build and run

Install the Rust stable toolchain, then run the CLI diagnostic:

```sh
cargo run -p ghost-fido
```

This command only prints scaffold status. A successful build does not indicate
that a virtual security key is available.

To develop the desktop app, install the platform prerequisites in
[`apps/desktop/README.md`](apps/desktop/README.md), then run from `apps/desktop`:

```sh
npm install
npm run tauri dev
```

## Planned platform adapters

- Linux: evaluate the UHID userspace interface and its device permissions.
- Windows: implement and package a native virtual USB/HID driver.
- macOS: validate the supported virtual HID mechanism and required Apple
  entitlements before committing to distribution.

Each adapter must be implemented and validated on its target operating system.
