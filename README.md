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

## Implementation and deferred validation

The CTAP/authenticator core, desktop approval lifecycle, and Linux UHID and
Windows UDE implementation paths are present. The T-022 lock-cancellation
behavior was implemented in [PR #228](https://github.com/soyuo/ghost-fido-key/pull/228).
Its target-machine acceptance run is deferred; the procedure and all six target
rows remain in [`docs/security-acceptance.md`](docs/security-acceptance.md) and
are still `Not run`. When ready, start the loopback RP using the commands in
[`tools/webauthn-test-rp/README.md`](tools/webauthn-test-rp/README.md), execute
both T-022 cases on each target, and record the observed RP outcome and evidence
in the procedure and [support matrix](docs/support-matrix.md). Closing the
tracking issue does not mean those tests passed or make a platform supported.

Linux retains the known unsound `glib 0.18.5` dependency advisory because the
stable Tauri/Wry dependency path has not moved to a patched GLib release. This
dependency work is deferred in
[issue #191](https://github.com/soyuo/ghost-fido-key/issues/191); the advisory
remains a Linux security release gate. This repository is implementation-ready
for later validation, not a supported or release-ready product.

## Workspace layout

- `apps/ghost-fido`: development entry point.
- `apps/desktop`: Tauri 2 desktop shell and React/TypeScript UI.
- `crates/ghost-fido-core`: platform-independent product and protocol domain.
- `crates/ghost-platform`: OS boundary and virtual-HID adapters.
- `resources/`: design notes and implementation plan.

## Build and run

For the desktop app, read the [local development and run guide](docs/development.md)
before installing dependencies. It lists the host prerequisites, first-run
commands, expected startup state, and platform-specific blockers.

Install the Rust stable toolchain, then run the CLI diagnostic if you only need
to check the shared Rust workspace:

```sh
cargo run -p ghost-fido
```

This command only prints diagnostic status; it does not start the desktop app
or create a virtual security key.

To start the desktop app, install the platform prerequisites and use the
first-run procedure in [`docs/development.md`](docs/development.md). The short
form, from `apps/desktop`, is:

```sh
npm ci
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
