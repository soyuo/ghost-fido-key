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
credential records held by the active store. Dropped credential records clear
their credential ID, RP hash/ID, user handle, and user labels, and dropped
management projections clear their copied RP/user labels. This is best-effort
cleanup only; it does not guarantee erasure of every compiler, allocator, OS,
provider, or hardware copy.

## T-022: Login-session lock during authentication

The desktop requires an explicit in-app approval followed by a native
confirmation before a signing request is approved. On Windows, the main window
registers for this login session's WTS lock notifications. A lock cancels all
pending approvals, blocks new requests, and leaves late native-dialog responses
unable to approve. Authenticator start also fails closed if the Windows lock
monitor is not installed or the session is locked. On Linux, the app monitors
the current systemd-logind session's `Lock` and `Unlock` signals and
`LockedHint`; a `Lock` signal cancels pending approvals, while `Unlock` only
clears the transition guard before the next session check re-reads `LockedHint`.
Authenticator start/approval fail closed if the monitor is unavailable or
logind reports the session locked. `LockedHint`
is supplied by the desktop environment, so this behavior is environment-dependent
and does not guarantee detection on every Linux desktop. On macOS, an observed
`NSWorkspace.sessionDidResignActiveNotification` and
`NSWorkspace.sessionDidBecomeActiveNotification` track user-session
transitions. New approvals are blocked while inactive, and switch-out
invalidates pending approvals within the polling interval. This is not
screen-lock detection; macOS still relies on the runtime's 30-second deadline for a screen lock or
when no session-switch notification is observed. The runtime deadline remains
a fallback on every platform.

For each target OS and architecture, use the local WebAuthn test RP and perform
both cases:

1. Start registration or authentication, then make the platform unavailable
   before responding to the desktop approval. On Windows, lock the OS session
   and confirm WTS lock notification cancels the request. On Linux, record
   whether logind's `Lock` signal cancels the request and whether the desktop
   environment updates `LockedHint`; if no signal is delivered, verify the
   request still expires within 30 seconds. On macOS, switch to another login
   session and verify the inactive session cannot deliver or approve the
   request; separately record whether the OS lock action emits a session-switch
   notification. If no notification is observed, keep the session locked until
   the 30-second deadline. Confirm the RP receives no successful registration
   or assertion.
2. Start another request, choose **Approve** so the native confirmation opens,
   then lock or switch out of the OS session. On Windows, unlock and attempt to
   confirm if the native dialog remains open; confirm the cancelled request
   cannot produce a credential or assertion. On Linux, attempt to confirm only after logind
   reports the session unlocked; any request that was cancelled or expired must
   remain unable to produce a credential or assertion. On macOS, after an
   observed user-session switch-out, verify the request is cancelled and any
   late native-dialog response is rejected after switching back in. While still
   switched out, attempt to start another request and confirm it is not
   delivered. If the lock action emits no session-switch notification, keep the
   session locked until the request deadline and verify late responses are
   rejected.

Record one row per target. A result on one architecture or OS does not cover the
others.

| Target | Expected lock policy | Case 1 | Case 2 | OS/build and evidence |
| --- | --- | --- | --- | --- |
| Ubuntu x64 | logind signal + `LockedHint`; 30-second fallback | Not run | Not run | None |
| Ubuntu ARM64 | logind signal + `LockedHint`; 30-second fallback | Not run | Not run | None |
| Windows x64 | Immediate WTS cancellation | Not run | Not run | None |
| Windows ARM64 | Immediate WTS cancellation | Not run | Not run | None |
| macOS Intel | Block while inactive; cancel on switch-out; screen-lock timeout fallback | Not run | Not run | None |
| macOS Apple silicon | Block while inactive; cancel on switch-out; screen-lock timeout fallback | Not run | Not run | None |

Do not mark T-022 verified until both cases pass on the relevant target and the
relying-party outcome is retained. Keep each affected support row unverified
until its observed behavior and RP outcome are recorded.
