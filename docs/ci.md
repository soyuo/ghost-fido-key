# Continuous integration

The `Cross-platform build` workflow runs on pull requests, pushes to `main`,
and manual dispatch. It checks the Rust workspace and builds the desktop
frontend on native Ubuntu 22.04 x64 and Ubuntu 24.04 ARM64, Windows, and macOS
runners. The ARM64 job checks the runner architecture before building and
packaging the desktop application.

The separate `Dependency security audit` workflow audits `Cargo.lock` against
RustSec advisories and `apps/desktop/package-lock.json` against npm advisories.
It runs on pull requests, pushes to `main`, weekly, and by manual dispatch. The
workflow has read-only repository permissions and checks frontend development
dependencies as well as runtime dependencies. A clean dependency audit is not a
substitute for protocol review, platform testing, browser interoperability, or
runtime security validation.

## Known unresolved Rust advisory

As of 2026-10-29, [`cargo audit`](https://rustsec.org/advisories/RUSTSEC-2024-0429)
reports `RUSTSEC-2024-0429` for `glib 0.18.5` on Linux. The locked Tauri 2.12.5
graph reaches it through GTK 0.18.2 and WebKitGTK. Tauri 2.12.5 requires
`gtk ^0.18`; Cargo rejects `gtk 0.19.0` because it does not satisfy that
constraint. The [gtk3-rs 0.19.0 release](https://github.com/gtk-rs/gtk3-rs/releases/tag/0.19.0)
uses gtk-rs-core 0.22, as confirmed in the
[upstream Tauri compatibility discussion](https://github.com/tauri-apps/tauri/issues/12564),
but it is not compatible with this Tauri 2 graph.

Tauri's upstream [GTK4/WebKitGTK 6 migration](https://github.com/tauri-apps/tauri/pull/14684)
is an unmerged Tauri 3 breaking change. Until a compatible maintained Tauri
release is available, keep the advisory visible; do not ignore it, alter crate
version metadata, or describe it as fixed. A source search found no
`VariantStrIter` or `array_iter_str` call sites in this repository or the
locked `tauri`, `tauri-runtime-wry`, `wry`, `tao`, `muda`, `gtk`, `webkit2gtk`,
and `glib` sources. That limits known use in the current application, but does
not remove the unsound API from the dependency graph or resolve the advisory.
The upstream migration is tracked for this project in
[issue #191](https://github.com/soyuo/ghost-fido-key/issues/191).

`cargo audit` treats unsound advisories as warnings by default, so the current
workflow reports this finding without failing. After the Linux dependency
graph moves to a compatible fixed release, add `cargo audit --deny unsound` to
make the resolved condition a CI gate and verify Linux x64 and ARM64 builds.

Each job runs `cargo fmt --all -- --check`,
`cargo check --workspace --locked`, `npm ci --prefix apps/desktop`, and
`npm --prefix apps/desktop run build`. The Ubuntu job installs the Linux system
dependencies listed in the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/)
plus `libdbus-1-dev` and `libclang-dev`, required by the Rust workspace's Linux
Secret Service and HID builds.

These jobs prove that the selected host toolchains compile the workspace and
frontend, and that Debian packages can be built for the listed Linux
architectures. They do not prove virtual HID enumeration, browser FIDO discovery,
WebAuthn registration or assertion, signed driver installation, Secure Enclave
availability, Secret Service runtime access, or packaged application behavior.
Those platform and runtime checks remain separate release requirements.

The native macOS runners also produce `.app` and `.dmg` bundles for their own
architectures. The Windows x64 runner produces an NSIS setup executable. These
unsigned development artifacts are retained by the workflow for seven days;
they are not signed or notarized, and the Windows UDE driver packages are
separate artifacts. CI checks package creation and expected output files only;
it does not install or launch these bundles, validate driver installation, or
establish platform support.
