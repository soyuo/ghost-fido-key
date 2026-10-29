# Ghost FIDO Key Desktop

Tauri 2 desktop shell with a React and TypeScript single-page frontend. The UI reads status from the Rust backend. Linux and Windows have platform-specific virtual HID adapters; macOS uses a Swift CoreHID bridge and remains unavailable until assigned product IDs and the signed virtual HID entitlement are configured.

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

The macOS CoreHID bridge is built as a static Swift library for the active Rust target. After the project receives assigned product identifiers, set `GHOST_FIDO_MACOS_VENDOR_ID` and `GHOST_FIDO_MACOS_PRODUCT_ID` to their decimal values while building. The app checks its signed entitlement before enabling the macOS start control; source entitlement files alone do not enable it.

Credential listing, individual deletion, and authenticator reset use the host key-store provider on Linux, Windows, and macOS. Stop the authenticator before managing credentials. Deletion removes the provider key before removing encrypted metadata; reset keeps metadata if a provider key cannot be deleted. These management commands do not establish virtual HID or browser WebAuthn support for the host.

The status view reports desktop approval, CTAP ClientPIN configuration, and native OS user verification separately. Desktop approval means an explicit per-request confirmation dialog is available. ClientPIN reports only whether a PIN verifier is configured; PIN material and retry state are not exposed. Native OS user verification remains marked not implemented because no biometric or OS-authentication provider is connected. A configured PIN or available dialog does not imply that a browser has discovered or interoperated with the virtual authenticator.

The app can also be previewed in a browser with `npm run dev`; the desktop-only status command is unavailable there. The existing command-line diagnostic remains available as the `ghost-fido` workspace package. Browser WebAuthn interoperability and a signed, entitled distribution still require separate macOS validation.
