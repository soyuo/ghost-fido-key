# Security acceptance procedures

These procedures are manual release evidence. CI and local builds do not prove
OS session behavior, HID transport, or browser acceptance. Record the tested OS
version and architecture, application build, result, and a reproducible
evidence reference. Leave results as `Not run` until observed on the target.

## T-022: Login-session lock during authentication

The desktop requires an explicit in-app approval followed by a native
confirmation before a signing request is approved. On Windows, the main window
registers for this login session's WTS lock notifications. A lock cancels all
pending approvals, blocks new requests, and leaves late native-dialog responses
unable to approve. Authenticator start also fails closed if the Windows lock
monitor is not installed or the session is locked. The runtime's 30-second
request deadline remains a fallback. Linux and macOS currently use timeout
cancellation and do not monitor native session-lock notifications.

For each target OS and architecture, use the local WebAuthn test RP and perform
both cases:

1. Start registration or authentication, lock the OS session before responding
   to the desktop approval. On Windows, confirm the request is cancelled
   immediately; on Linux and macOS, remain locked until the 30-second deadline.
   Unlock and confirm the RP receives no successful registration or assertion.
2. Start another request, choose **Approve** so the native confirmation opens,
   lock the OS session. On Windows, unlock and attempt to confirm if the native
   dialog remains open; confirm the cancelled request cannot produce a
   credential or assertion. On Linux and macOS, keep the session locked until
   the request deadline, then verify any late response is rejected.

Record one row per target. A result on one architecture or OS does not cover the
others.

| Target | Expected lock policy | Case 1 | Case 2 | OS/build and evidence |
| --- | --- | --- | --- | --- |
| Ubuntu x64 | 30-second timeout | Not run | Not run | None |
| Ubuntu ARM64 | 30-second timeout | Not run | Not run | None |
| Windows x64 | Immediate WTS cancellation | Not run | Not run | None |
| Windows ARM64 | Immediate WTS cancellation | Not run | Not run | None |
| macOS Intel | 30-second timeout | Not run | Not run | None |
| macOS Apple silicon | 30-second timeout | Not run | Not run | None |

Do not mark T-022 verified until both cases pass on the relevant target and the
relying-party outcome is retained. Keep each affected support row unverified
until its observed behavior and RP outcome are recorded.
