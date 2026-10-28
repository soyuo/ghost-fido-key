# Ghost FIDO Key Desktop

Tauri 2 desktop shell with a React and TypeScript single-page frontend. The UI reads status from the Rust backend; the current virtual HID backend deliberately reports unavailable on every platform.

## Prerequisites

- All platforms: Rust via rustup and Node.js LTS.
- Windows: Microsoft C++ Build Tools with **Desktop development with C++**, and Microsoft Edge WebView2 Runtime.
- macOS: Xcode Command Line Tools for desktop development (`xcode-select --install`).
- Ubuntu/Debian Linux: `libwebkit2gtk-4.1-dev`, `build-essential`, `curl`, `wget`, `file`, `libxdo-dev`, `libssl-dev`, `libayatana-appindicator3-dev`, and `librsvg2-dev`.

For current, distribution-specific packages and version requirements, see the [official Tauri prerequisites](https://v2.tauri.app/start/prerequisites/).

## Development

From this directory:

```sh
npm install
npm run tauri dev
```

Build the frontend with `npm run build`. Build a desktop bundle on a configured host with `npm run tauri build`.

The app can also be previewed in a browser with `npm run dev`; the desktop-only status command is unavailable there. The existing command-line diagnostic remains available as the `ghost-fido` workspace package. This scaffold does not attach a virtual device or process FIDO requests.
