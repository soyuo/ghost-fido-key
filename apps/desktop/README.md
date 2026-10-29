# Ghost FIDO Key Desktop

Tauri 2 desktop shell with a React and TypeScript single-page frontend. The UI reads status from the Rust backend. Linux and Windows have platform-specific virtual HID adapters; macOS uses a Swift CoreHID bridge and remains unavailable until assigned product IDs and the signed virtual HID entitlement are configured.

No OS/browser combination is currently declared supported. The [platform and browser support matrix](../../docs/support-matrix.md) separates CI build evidence from signed installation, virtual HID runtime, and end-to-end WebAuthn validation.

## Prerequisites

- All platforms: Rust via rustup and Node.js LTS.
- Windows: Microsoft C++ Build Tools with **Desktop development with C++**, and Microsoft Edge WebView2 Runtime.
- macOS: Xcode Command Line Tools for desktop development (`xcode-select --install`) and Swift 6.0 or newer.
- Ubuntu/Debian Linux: `libwebkit2gtk-4.1-dev`, `build-essential`, `curl`, `wget`, `file`, `libxdo-dev`, `libssl-dev`, `libayatana-appindicator3-dev`, and `librsvg2-dev`.

For current, distribution-specific packages and version requirements, see the [official Tauri prerequisites](https://v2.tauri.app/start/prerequisites/).

## Development

From this directory:

```sh
npm install
npm run tauri dev
```

Build the frontend with `npm run build`. Build a desktop bundle on a configured host with `npm run tauri build`.

The packaged WebView Content Security Policy permits Tauri IPC and the app's bundled asset origins. The Vite development server and HMR origins are listed only in `devCsp`; they are not allowed by the production `csp`.

The macOS CoreHID bridge is built as a static Swift library for the active Rust target. After the project receives assigned product identifiers, set `GHOST_FIDO_MACOS_VENDOR_ID` and `GHOST_FIDO_MACOS_PRODUCT_ID` to their decimal values while building. The app checks its signed entitlement before enabling the macOS start control; source entitlement files alone do not enable it.

Credential listing, individual deletion, and authenticator reset use the host key-store provider on Linux, Windows, and macOS. Stop the authenticator before managing credentials. Deletion removes the provider key before removing encrypted metadata; if metadata cleanup fails, retrying deletion treats an already-missing provider key as deleted and can finish removing the metadata. Reset keeps metadata if a provider key cannot be deleted. Provider outages and metadata-storage failures still require a successful retry. These management commands do not establish virtual HID or browser WebAuthn support for the host.

PIN changes, credential deletion, and authenticator reset require confirmation from a native system dialog initiated inside the Rust command. These commands do not accept a frontend-supplied confirmation flag; canceling or closing the dialog leaves the operation unapplied.

On Linux, starting the authenticator also opens a native warning that explains the software-backed signing-key storage risk. The Rust start command requires that dialog to be accepted before it creates the session-scoped consent token. Canceling or closing it leaves the runtime stopped. Windows and macOS continue to require platform-protected signing keys and do not show this software-key consent dialog.

The status view reports request approval, CTAP ClientPIN configuration, and native OS user verification separately. Each signing request is shown in the desktop UI and then requires a native system confirmation before Rust returns an approved decision; a Tauri caller cannot authorize signing by invoking the approval command alone. Canceling either prompt rejects the request, and the runtime request timeout remains authoritative. This dialog is explicit user approval, not biometric or native OS user verification. ClientPIN reports only whether a PIN verifier is configured; PIN material and retry state are not exposed. Native OS user verification remains unimplemented because no biometric or OS-authentication provider is connected. A configured PIN or available dialog does not imply that a browser has discovered or interoperated with the virtual authenticator.

When the authenticator is stopped, desktop settings can set or change the local authenticator PIN. This management path applies the same PIN policy, verifier format, protected storage, and persistent retry counter used by CTAP ClientPIN. It receives PINs through the local Tauri command and does not replace the CTAP ClientPIN key-agreement exchange used by external clients. Wrong current-PIN attempts consume the same retry budget; a blocked PIN currently requires authenticator reset.

The Rust IPC boundary rejects current or new PIN strings longer than 63 UTF-8 bytes before showing a confirmation dialog, hashing, or changing retry state. Approval responses must use the exact lowercase, hyphenated UUID form generated for a pending request; malformed identifiers are rejected before pending state is accessed.

The app can also be previewed in a browser with `npm run dev`; the desktop-only status command is unavailable there. The existing command-line diagnostic remains available as the `ghost-fido` workspace package. Browser WebAuthn interoperability and a signed, entitled distribution still require separate macOS validation.

## Local diagnostics

The desktop app writes a best-effort operational event log to `events.log` in the operating system's recommended application log directory for `com.ghostfido.desktop`:

- Linux: `$XDG_DATA_HOME/com.ghostfido.desktop/logs`, or `$HOME/.local/share/com.ghostfido.desktop/logs` when `XDG_DATA_HOME` is unset.
- macOS: `~/Library/Logs/com.ghostfido.desktop`.
- Windows: `%LOCALAPPDATA%\com.ghostfido.desktop\logs`.

The file is limited to 1 MiB; when it reaches that size, the existing contents are cleared before new events are written. If the log directory is unavailable or a write fails, logging is silently disabled and does not affect authenticator or credential operations. Events record only fixed operation names and coarse outcomes, such as runtime lifecycle, local approval, PIN configuration, credential deletion, and reset. They omit RP names and identifiers, user names, credential IDs, PINs and PIN hashes, key material, request IDs, and CTAP/CBOR/HID payloads. This is a local diagnostic aid, not a tamper-proof audit record.
