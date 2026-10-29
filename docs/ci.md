# Continuous integration

The `Cross-platform build` workflow runs on pull requests, pushes to `main`,
and manual dispatch. It checks the Rust workspace and builds the desktop
frontend on native Ubuntu 22.04 x64 and Ubuntu 24.04 ARM64, Windows, and macOS
runners. The ARM64 job checks the runner architecture before building and
packaging the desktop application.

Each job runs `cargo fmt --all -- --check`,
`cargo check --workspace --locked`, `npm ci --prefix apps/desktop`, and
`npm --prefix apps/desktop run build`. The Ubuntu job installs the Linux system
dependencies listed in the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/)
and `libclang-dev`, required by the Rust workspace's Linux HID build.

These jobs prove that the selected host toolchains compile the workspace and
frontend, and that Debian packages can be built for the listed Linux
architectures. They do not prove virtual HID enumeration, browser FIDO discovery,
WebAuthn registration or assertion, signed driver installation, Secure Enclave
availability, Secret Service runtime access, or packaged application behavior.
Those platform and runtime checks remain separate release requirements.
