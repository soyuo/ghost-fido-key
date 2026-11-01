# Local development and run guide

This guide starts the Ghost FIDO Key desktop shell from a source checkout. It
does not install a signed product build or validate a virtual authenticator.
No OS/browser combination is currently declared supported; use the
[support matrix](support-matrix.md) for the evidence required to change that
status.

## Before the first run

Install the following on the development machine:

- Rust stable with the MSVC host toolchain on Windows. Install it with
  [rustup](https://rustup.rs/); the workspace declares Rust 1.90 as its
  minimum, so the active toolchain must meet that minimum.
- Node.js 22.12 or newer and npm. The desktop lockfile requires Node 20.19+
  or 22.12+, and the optional WebAuthn test RP requires Node 22+.
- The native dependencies for Tauri 2 on the host OS. Follow the current
  [official Tauri prerequisites](https://v2.tauri.app/start/prerequisites/)
  because package names and platform requirements can change.

Host-specific notes:

- **Windows:** install Microsoft C++ Build Tools with **Desktop development
  with C++** selected. Tauri renders the app with Microsoft Edge WebView2; it is
  included on current Windows releases. Use a terminal opened after installing
  the build tools so the Rust MSVC linker is available.
- **Ubuntu/Debian Linux:** install the GTK/WebKitGTK development packages listed
  in [the desktop prerequisites](../apps/desktop/README.md#prerequisites).
  Access to `/dev/uhid` is needed for a later Linux authenticator runtime
  attempt, but is not needed just to build and open the UI.
- **macOS:** install Xcode Command Line Tools and Swift 6.0 or newer. CoreHID
  runtime use additionally requires product-assigned IDs and Apple's approved
  virtual-HID entitlement; source files alone do not enable it.

Confirm the tools are visible in a new terminal:

```sh
rustc --version
rustup show active-toolchain
node --version
npm --version
```

The active Rust version must be 1.90 or newer. On Windows, `rustup show
active-toolchain` should report an MSVC toolchain (for example,
`stable-x86_64-pc-windows-msvc`).

## Install and launch the desktop app

From the repository root, install the locked frontend dependencies and start
the Tauri development app:

```sh
cd apps/desktop
npm ci
npm run tauri dev
```

The first launch compiles the Rust backend and frontend and can take several
minutes. Keep the terminal open while developing; it runs Vite on
`http://localhost:1420` and reports backend/compiler errors. Stop the app with
`Ctrl+C` in that terminal. The Vite port is fixed; stop another process using
port 1420 if startup reports that the port is already occupied.

To rebuild the frontend or create a host development bundle:

```sh
npm run build
npm run tauri build
```

`npm run dev` alone opens only the browser preview. Desktop-only Tauri commands
are unavailable in that preview. `cargo run -p ghost-fido` is a separate CLI
diagnostic and does not start the desktop app.

## What a successful launch means

A visible desktop window means that the Tauri app opened. It does not prove the
platform backend is configured, a virtual HID device attached, a browser
discovered an authenticator, or a WebAuthn ceremony succeeded. The status view
reports local prerequisites; `backend ready` is not browser-support evidence.

The remaining platform gates are external to an ordinary development launch:

- **Windows:** the UDE development driver package is unsigned, defaults to no
  product VID/PID, and has not been target-machine validated. Driver signing,
  assigned product IDs, installation and elevation, restart/removal behavior,
  and HID report exchange must be addressed before browser testing. See the
  [Windows UDE guide](../platforms/windows/ude/README.md).
- **Linux:** the host must expose `/dev/uhid` with the documented permissions;
  device attach/report exchange and package lifecycle still need target-host
  validation. Linux signing-key storage is software-backed and requires the
  documented consent flow.
- **macOS:** the bridge remains unavailable until product IDs and Apple's
  signed virtual-HID entitlement are configured. Development signing does not
  prove distribution entitlement or runtime support.

Do not install an unsigned development driver or change driver-signing policy
as a substitute for the documented Windows validation process. Do not use
unassigned or third-party USB vendor/product IDs.

## Optional: local WebAuthn test RP

Run this only after an authenticator backend can be attached on the target
machine. The loopback RP verifies registration and assertion responses; it
does not provide a virtual authenticator or prove HID discovery.

```sh
npm ci --prefix tools/webauthn-test-rp
npm start --prefix tools/webauthn-test-rp
```

Open `http://localhost:8787` in the same Chrome or Edge profile. Follow the
[RP procedure](../tools/webauthn-test-rp/README.md) and record each protocol
layer separately in the [support matrix](support-matrix.md). Use only test
accounts; the RP keeps its single credential in process memory and clears it
when stopped.

## If startup fails

1. Check the first error in the terminal where `npm run tauri dev` is running.
2. Confirm Rust, the host's native build tools, Node.js, and npm are visible in
   a newly opened terminal.
3. If frontend packages are missing or inconsistent, stop the app and rerun
   `npm ci` from `apps/desktop`.
4. If Tauri reports a missing host library or SDK, install the prerequisite for
   that host from the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/)
   page, then reopen the terminal.
5. If compilation succeeds but the authenticator cannot start, use the
   platform guide and status detail to distinguish missing permission, driver,
   entitlement, product identity, or runtime validation. A successful compile
   cannot resolve those platform gates.

When reporting a blocker, include the OS version and architecture, output of
the four version commands above, the exact command run, and the first complete
error message. Do not include PINs, credential data, private keys, or other
secrets.
