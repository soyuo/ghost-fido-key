# Security acceptance procedures

These procedures are manual release evidence. CI and local builds do not prove
OS session behavior, HID transport, or browser acceptance. Record the tested OS
version and architecture, application build, result, and a reproducible
evidence reference. Leave results as `Not run` until observed on the target.

## Secret-memory handling

ClientPIN and `hmac-secret` use HMAC-SHA256 with zeroization enabled for the
SHA-256 digest state, and the application clears its full-length HMAC output
buffers after use. This does not guarantee that every dependency-owned
intermediate is erased: the current RustCrypto HMAC implementation creates a
normalized key block and an inner digest temporary that are not zeroized by its
zeroize feature. Treat this as a known memory-hygiene limitation; do not claim
complete erasure of all HMAC intermediates.

On Linux and macOS, the AES-GCM credential-store cipher enables zeroization for
its AES-GCM, GHASH, and POLYVAL dependency state. This clears the AES-GCM
derived GHASH key temporary and the GHASH/POLYVAL state when their values are
dropped. This does not guarantee erasure of every compiler, hardware, or
dependency-owned intermediate; do not claim complete cryptographic memory
erasure.

Credential-store decrypted payloads are returned in zeroizing buffers. Record
serialization clears both its temporary CBOR value tree and encoded payload
after protection during saves, reset initialization, and schema migration. On
Windows, the copied DPAPI result and the OS-allocated DPAPI output buffer are
wiped before release. This covers these transient buffers; it does not erase
credential records held by the active store or guarantee erasure of every
compiler, OS, provider, or hardware copy.

## T-022: Login-session lock during authentication

The desktop requires an explicit in-app approval followed by a native
confirmation before a signing request is approved. On Windows, the main window
registers for this login session's WTS lock notifications. A lock cancels all
pending approvals, blocks new requests, and leaves late native-dialog responses
unable to approve. Authenticator start also fails closed if the Windows lock
monitor is not installed or the session is locked. On Linux, the app monitors
the current systemd-logind session's `Lock` signal and `LockedHint`; a `Lock`
signal cancels pending approvals, and authenticator start/approval fail closed
if the monitor is unavailable or logind reports the session locked. `LockedHint`
is supplied by the desktop environment, so this behavior is environment-dependent
and does not guarantee detection on every Linux desktop. macOS currently uses
timeout cancellation and does not monitor native session-lock notifications.
The runtime's 30-second request deadline remains a fallback on every platform.

For each target OS and architecture, use the local WebAuthn test RP and perform
both cases:

1. Start registration or authentication, lock the OS session before responding
   to the desktop approval. On Windows, confirm WTS lock notification cancels
   the request. On Linux, record whether logind's `Lock` signal cancels the
   request and whether the desktop environment updates `LockedHint`; if no
   signal is delivered, verify the request still expires within 30 seconds.
   On macOS, remain locked until the 30-second deadline. Unlock and confirm the
   RP receives no successful registration or assertion.
2. Start another request, choose **Approve** so the native confirmation opens,
   lock the OS session. On Windows, unlock and attempt to confirm if the native
   dialog remains open; confirm the cancelled request cannot produce a
   credential or assertion. On Linux, attempt to confirm only after logind
   reports the session unlocked; any request that was cancelled or expired must
   remain unable to produce a credential or assertion. On macOS, keep the
   session locked until the request deadline, then verify any late response is
   rejected.

Record one row per target. A result on one architecture or OS does not cover the
others.

| Target | Expected lock policy | Case 1 | Case 2 | OS/build and evidence |
| --- | --- | --- | --- | --- |
| Ubuntu x64 | logind signal + `LockedHint`; 30-second fallback | Not run | Not run | None |
| Ubuntu ARM64 | logind signal + `LockedHint`; 30-second fallback | Not run | Not run | None |
| Windows x64 | Immediate WTS cancellation | Not run | Not run | None |
| Windows ARM64 | Immediate WTS cancellation | Not run | Not run | None |
| macOS Intel | 30-second timeout | Not run | Not run | None |
| macOS Apple silicon | 30-second timeout | Not run | Not run | None |

Do not mark T-022 verified until both cases pass on the relevant target and the
relying-party outcome is retained. Keep each affected support row unverified
until its observed behavior and RP outcome are recorded.
