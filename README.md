# Ghost FIDO Key

Cross-platform software FIDO2 authenticator prototype. The shared application
backend is Rust, with a Tauri 2 desktop shell using React and TypeScript. The
repository includes Linux and Windows virtual-HID adapter paths and a macOS
CoreHID bridge.

## Current status

The workspace implements the CTAP authenticator, credential and key storage,
desktop approval flow, and Linux/Windows virtual-HID integration paths. The
macOS CoreHID bridge remains unavailable until assigned product identifiers
and a signed virtual-HID entitlement are configured.

Target installation, virtual-HID report exchange, and browser WebAuthn
interoperability have not been demonstrated for the required platform matrix.
No OS/browser combination is currently declared supported. See the
[platform and browser support matrix](docs/support-matrix.md) for evidence and
remaining validation requirements; code presence and CI builds alone do not
establish support.

## Workspace layout

- `apps/ghost-fido`: development entry point.
- `apps/desktop`: Tauri 2 desktop shell and React/TypeScript UI.
- `crates/ghost-fido-core`: platform-independent product and protocol domain.
- `crates/ghost-platform`: OS boundary and virtual-HID adapters.
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

## Platform adapter status

- Linux: the UHID adapter and package permission path are implemented; target
  installation and report exchange remain unverified.
- Windows: the UDE integration and driver package path are implemented; the
  unsigned package has not been installed or runtime-validated on a target.
- macOS: the CoreHID bridge is present but remains unavailable pending assigned
  product identifiers and the signed virtual-HID entitlement.

Each platform still requires target-device and browser validation before it can
be declared supported.
