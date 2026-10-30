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
| Windows, x64 | Windows CI checks pass; unsigned x64 desktop installer and x64 UDE driver development package are produced. [CI run](https://github.com/soyuo/ghost-fido-key/actions/runs/40870465919), [UDE package work](https://github.com/soyuo/ghost-fido-key/pull/173), [desktop bundle work](https://github.com/soyuo/ghost-fido-key/pull/181). | CI package is unsigned and has not been installed or runtime-validated. UDE status reports the four source-implemented capability bits (`0x0f`) after [PR #242](https://github.com/soyuo/ghost-fido-key/pull/242). With a valid assigned identity and exact report profile, Rust reports `Configured` and permits a runtime attempt after [PR #246](https://github.com/soyuo/ghost-fido-key/pull/246); this does not validate attach/report exchange or browser interoperability. | Build validated only; runtime and browser unverified. |
| Windows, ARM64 | Windows CI builds and packages the ARM64 UDE driver; the dedicated native ARM64 desktop job builds an unsigned NSIS installer and verifies the application executable's PE machine type. [Passing CI run](https://github.com/soyuo/ghost-fido-key/actions/runs/40877570291), [installer implementation](https://github.com/soyuo/ghost-fido-key/pull/196), [UDE package work](https://github.com/soyuo/ghost-fido-key/pull/173). | CI driver and desktop packages are unsigned and have not been installed or runtime-validated. UDE status reports the four source-implemented capability bits (`0x0f`) after [PR #242](https://github.com/soyuo/ghost-fido-key/pull/242). With a valid assigned identity and exact report profile, Rust reports `Configured` and permits a runtime attempt after [PR #246](https://github.com/soyuo/ghost-fido-key/pull/246); this does not validate attach/report exchange or browser interoperability. | Driver and desktop package builds only; runtime and browser unverified. |
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

The development-only [local WebAuthn test RP](../tools/webauthn-test-rp/README.md)
provides a loopback relying party for the registration and assertion stages.
It does not provide an authenticator or replace the OS, browser-discovery, HID,
or CTAP evidence required for a support result.

| OS / architecture | Browser | OS build / browser version | Device enumeration | FIDO discovery | CTAPHID exchange | CTAP2 execution | Registration | Assertion | RP signature verification | Evidence link | Result |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Ubuntu LTS x64 | Chrome | Not recorded | Not run | Not run | Not run | Not run | Not run | Not run | Not recorded | None | Not verified |
| Ubuntu LTS x64 | Edge | Not recorded | Not run | Not run | Not run | Not run | Not run | Not run | Not recorded | None | Not verified |
| Ubuntu LTS ARM64 | Chrome | Not recorded | Not run | Not run | Not run | Not run | Not run | Not run | Not recorded | None | Not verified |
| Ubuntu LTS ARM64 | Edge | Not recorded | Not run | Not run | Not run | Not run | Not run | Not run | Not recorded | None | Not verified |
| Windows x64 | Chrome | Not recorded | Not run | Not run | Not run | Not run | Not run | Not run | Not recorded | None | Not verified |
| Windows x64 | Edge | Not recorded | Not run | Not run | Not run | Not run | Not run | Not run | Not recorded | None | Not verified |
| Windows ARM64 | Chrome | Not recorded | Not run | Not run | Not run | Not run | Not run | Not run | Not recorded | None | Not verified |
| Windows ARM64 | Edge | Not recorded | Not run | Not run | Not run | Not run | Not run | Not run | Not recorded | None | Not verified |
| macOS Intel | Chrome | Not recorded | Not run | Not run | Not run | Not run | Not run | Not run | Not recorded | None | Not verified |
| macOS Intel | Edge | Not recorded | Not run | Not run | Not run | Not run | Not run | Not run | Not recorded | None | Not verified |
| macOS Apple silicon | Chrome | Not recorded | Not run | Not run | Not run | Not run | Not run | Not run | Not recorded | None | Not verified |
| macOS Apple silicon | Edge | Not recorded | Not run | Not run | Not run | Not run | Not run | Not run | Not recorded | None | Not verified |

### Manual ceremony scenarios

For each OS/browser row above, copy this record and retain the outcome and a
reproducible evidence link. A ceremony result does not substitute for lower
layers such as device enumeration or CTAPHID.

| Scenario | Required result to record | Outcome | Evidence link / notes |
| --- | --- | --- | --- |
| User approval | Approved request reaches the RP; app denial is rejected. | Not run | None |
| PIN / user verification | Record configured UV request, PIN result, and signed WebAuthn UV flag. | Not run | None |
| Discoverable credential | Registration requests resident key; assertion omits allow-list. | Not run | None |
| Allow-list credential | Assertion includes the registered credential ID. | Not run | None |
| Browser cancellation | Cancel the browser prompt and record app, browser, and RP outcomes. | Not run | None |
| Authenticator denial | Deny in the native approval flow and record the RP outcome. | Not run | None |
| Timeout | Record requested timeout and the browser-observed timeout behavior. | Not run | None |
| Reauthentication | Complete another assertion with the same RP credential. | Not run | None |
| After authenticator reset | Reset through the desktop app, then record registration and assertion behavior. | Not run | None |

The login-session lock procedure in
[`docs/security-acceptance.md`](security-acceptance.md) is also required for
stage 12. It has separate per-OS/architecture results and remains unverified
until run on the target machines.

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

The current Linux dependency audit retains two GTK 0.18 graph warnings: the
unsound GLib advisory, tracked by
[issue #191](https://github.com/soyuo/ghost-fido-key/issues/191), and an
unmaintained `proc-macro-error` dependency. The GLib finding remains a security
release gate; passing the current build workflow does not resolve either
warning.

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
