# Security acceptance procedures

These procedures are manual release evidence. CI and local builds do not prove
OS session behavior, HID transport, or browser acceptance. Record the tested OS
version and architecture, application build, result, and a reproducible
evidence reference. Leave results as `Not run` until observed on the target.

## T-022: Login-session lock during authentication

The desktop requires an explicit in-app approval followed by a native
confirmation before a signing request is approved. If the login session locks
while a request is pending, no approval is inferred from the lock or unlock
transition. The request expires at the runtime's 30-second deadline. The
backend removes the pending request, emits `approval-cancelled`, and rejects a
late response. This is a timeout policy; the app does not currently monitor
OS-specific session-lock notifications or stop the runtime immediately.

For each target OS and architecture, use the local WebAuthn test RP and perform
both cases:

1. Start registration or authentication, lock the OS session before responding
   to the desktop approval, remain locked until the 30-second request deadline,
   then unlock. Confirm the approval card is removed and the RP receives no
   successful registration or assertion.
2. Start another request, choose **Approve** so the native confirmation opens,
   lock the OS session until the request deadline, then unlock. If the native
   dialog remains open, close it or attempt to confirm. Confirm the expired
   request cannot produce a credential or assertion and any late response is
   rejected.

Record one row per target. A result on one architecture or OS does not cover the
others.

| Target | Case 1 | Case 2 | OS/build and evidence |
| --- | --- | --- | --- |
| Ubuntu x64 | Not run | Not run | None |
| Ubuntu ARM64 | Not run | Not run | None |
| Windows x64 | Not run | Not run | None |
| Windows ARM64 | Not run | Not run | None |
| macOS Intel | Not run | Not run | None |
| macOS Apple silicon | Not run | Not run | None |

Do not mark T-022 verified until both cases pass on the relevant target and the
relying-party outcome is retained. If behavior differs from the timeout policy,
keep the affected support row unverified and track a native session-monitor
implementation separately.
