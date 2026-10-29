# Platform and browser support evidence

**Status: no OS/browser combination is currently declared supported.** This page
tracks evidence required by [`resources/STEP.md`](../resources/STEP.md) and
[`resources/SPEC.md`](../resources/SPEC.md). A successful compile or package
build proves only that build step; it does not prove that an OS created a
virtual authenticator or that a browser completed WebAuthn.

## Platform evidence

| Required platform | Current CI evidence | Device, signing, and installation evidence | Platform status |
| --- | --- | --- | --- |
| Ubuntu LTS, x64 | Ubuntu 22.04 x64 workspace and Debian package build pass; package contains the UHID udev rule. [CI run](https://github.com/soyuo/ghost-fido-key/actions/runs/40870465919), [udev package work](https://github.com/soyuo/ghost-fido-key/pull/171). | No target-machine UHID attach/report exchange, clean install/update/remove, or recovery evidence is recorded. | Build validated only. Linux signing keys use Secret Service software storage after explicit session consent. |
| Ubuntu LTS, ARM64 | Native Ubuntu 24.04 ARM64 workspace and Debian package build pass. [CI run](https://github.com/soyuo/ghost-fido-key/actions/runs/40870465919), [native ARM64 CI work](https://github.com/soyuo/ghost-fido-key/pull/175). | No target-machine UHID attach/report exchange, clean install/update/remove, or recovery evidence is recorded. | Build validated only. |
| Windows, x64 | Windows CI checks pass; unsigned x64 desktop installer and x64 UDE driver development package are produced. [CI run](https://github.com/soyuo/ghost-fido-key/actions/runs/40870465919), [UDE package work](https://github.com/soyuo/ghost-fido-key/pull/173), [desktop bundle work](https://github.com/soyuo/ghost-fido-key/pull/181). | The driver package is unsigned and has not been installed or runtime-validated. The driver reports `CONTROLLER_READY` only; Rust requires capability mask `0x0f`, so the backend remains unavailable. | Build validated only; not installable as a supported release. |
| Windows, ARM64 | Windows CI builds and packages the ARM64 UDE driver; the dedicated native ARM64 desktop job builds an unsigned NSIS installer and verifies the application executable's PE machine type. [CI workflow](../.github/workflows/cross-platform-build.yml), [UDE package work](https://github.com/soyuo/ghost-fido-key/pull/173), [desktop bundle issue](https://github.com/soyuo/ghost-fido-key/issues/195). | The driver and desktop packages are unsigned and have not been installed or runtime-validated. The UDE driver reports only `CONTROLLER_READY`; Rust requires capability mask `0x0f`. | Driver and desktop package builds only; runtime and browser unverified. |
| macOS, Intel | macOS 15 Intel CI builds the desktop development bundle and CoreHID bridge. [CI run](https://github.com/soyuo/ghost-fido-key/actions/runs/40870465919), [bundle work](https://github.com/soyuo/ghost-fido-key/pull/181). | Bundle is unsigned. No assigned product VID/PID, approved virtual-HID entitlement, installation, device enumeration, or report exchange has been demonstrated. | Build validated only; backend remains unavailable without assigned IDs and signed entitlement. |
| macOS, Apple silicon | macOS 15 Apple silicon CI builds the desktop development bundle and CoreHID bridge. [CI run](https://github.com/soyuo/ghost-fido-key/actions/runs/40870465919), [bundle work](https://github.com/soyuo/ghost-fido-key/pull/181). | Bundle is unsigned. No assigned product VID/PID, approved virtual-HID entitlement, installation, device enumeration, or report exchange has been demonstrated. | Build validated only; backend remains unavailable without assigned IDs and signed entitlement. |

The CI labels are build environments, not a claim that every security-supported
OS release in the product scope has been validated. Windows driver catalog
packaging targets Windows 11 24H2 and 25H2, but the unsigned catalog is not a
signed driver or an installation result. The macOS CoreHID API requires macOS
15 or later and Apple's virtual-HID entitlement. Linux's current key-storage
mode is software-backed and requires explicit consent; it is not hardware
backing.
The Windows TPM-backed CNG and macOS Secure Enclave/Keychain provider paths
also lack retained target-device evidence in this matrix; provider source and
build success do not establish the actual key protection available on a host.

## Required browser evidence

For every row, the browser version and OS build must be recorded, followed by
device enumeration, FIDO discovery, CTAPHID exchange, CTAP2 execution, RP
registration, assertion, and server-side signature verification. No such
end-to-end result is currently recorded for any combination.

| OS / architecture | Browser | OS / browser versions | Registration | Assertion | Server signature verification | Result |
| --- | --- | --- | --- | --- | --- | --- |
| Ubuntu LTS x64 | Chrome | Not recorded | Not run | Not run | Not recorded | Not verified |
| Ubuntu LTS x64 | Edge | Not recorded | Not run | Not run | Not recorded | Not verified |
| Ubuntu LTS ARM64 | Chrome | Not recorded | Not run | Not run | Not recorded | Not verified |
| Ubuntu LTS ARM64 | Edge | Not recorded | Not run | Not run | Not recorded | Not verified |
| Windows x64 | Chrome | Not recorded | Not run | Not run | Not recorded | Not verified |
| Windows x64 | Edge | Not recorded | Not run | Not run | Not recorded | Not verified |
| Windows ARM64 | Chrome | Not recorded | Not run | Not run | Not recorded | Not verified |
| Windows ARM64 | Edge | Not recorded | Not run | Not run | Not recorded | Not verified |
| macOS Intel | Chrome | Not recorded | Not run | Not run | Not recorded | Not verified |
| macOS Intel | Edge | Not recorded | Not run | Not run | Not recorded | Not verified |
| macOS Apple silicon | Chrome | Not recorded | Not run | Not run | Not recorded | Not verified |
| macOS Apple silicon | Edge | Not recorded | Not run | Not run | Not recorded | Not verified |

## Release gates

A platform/browser row can be changed to supported only after evidence is linked
for all of the following:

1. Signed application and, where applicable, signed driver or approved
   entitlement installed on the recorded OS build.
2. Virtual HID creation, enumeration, bidirectional 64-byte report exchange,
   detach, and recovery after abnormal exit.
3. Chrome or Edge registration and reauthentication against the same test RP,
   with the RP's server-side signature verification result retained.
4. Install, update, and removal behavior, including device cleanup and the
   documented user-data policy.
5. The platform's key-protection level and any site or authenticator-policy
   limitations recorded alongside the result.

The current Linux dependency audit also retains an unsound GLib advisory,
tracked by [issue #191](https://github.com/soyuo/ghost-fido-key/issues/191).
That issue is a security release gate; passing the current build workflow does
not resolve it.

## Evidence sources

- [Cross-platform build workflow](../.github/workflows/cross-platform-build.yml)
- [Linux UHID boundary](linux-uhid.md)
- [Windows UDE driver boundary](../platforms/windows/ude/README.md)
- [macOS CoreHID boundary](../platforms/macos/corehid/README.md)
- [Desktop app setup and current platform limitations](../apps/desktop/README.md)
- [Debian udev package refresh, PR #171](https://github.com/soyuo/ghost-fido-key/pull/171)
- [Windows UDE development packages, PR #173](https://github.com/soyuo/ghost-fido-key/pull/173)
- [Native Ubuntu ARM64 CI, PR #175](https://github.com/soyuo/ghost-fido-key/pull/175)
- [Unsigned development bundles, PR #181](https://github.com/soyuo/ghost-fido-key/pull/181)

Update this matrix only when a new result is directly observed and its
reproduction evidence can be retained. Do not infer runtime or browser support
from a CI build, package archive, source implementation, or entitlement file.
