# Desktop approval flow

The desktop `UserVerification` provider publishes an `approval-request` Tauri
event containing a random one-time request ID, relying-party ID and optional
name, action, and timeout. The React UI renders the RP context as text and
requires the user to choose **Approve** or **Deny**. The UI returns that choice
through the `respond_approval` command.

Each pending ID maps to one response channel. The provider removes the ID when
it receives a decision or when its deadline expires, so unknown, replayed, and
late decisions are rejected. Denial returns `VerificationDecision::Rejected`;
expiry returns the platform timeout error and emits `approval-cancelled` so the
UI removes the expired prompt. A matching CTAPHID CANCEL sends
`VerificationDecision::Cancelled`, emits the same event, and clears the UI
prompt. Cancellation maps to CTAP2 `KEEPALIVE_CANCEL`. Failure to deliver an
event or receive a response fails closed. The event does not include credential
IDs, user handles, key references, or private key material.

If the desktop session locks while approval is pending, the request remains
unapproved and expires at its normal deadline (30 seconds in the desktop
runtime). Unlocking does not restore the expired request. The app does not
currently subscribe to an OS-specific lock notification; verify this timeout
behavior on target systems using the T-022 procedure in
[`security-acceptance.md`](security-acceptance.md).

This is the desktop approval boundary only. The Tauri app still has no live HID
request source, so it does not receive browser authentication requests.

## Authenticator runtime ownership

The desktop app holds an exclusive cross-process lock in its app-data directory
for the lifetime of an authenticator runtime. A second Ghost FIDO Key process
cannot attach another virtual HID authenticator while that lock is held. The
runtime worker retains the lock until it exits; startup/runtime failure, normal
stop, or process exit releases it. An unavailable lock fails startup before
runtime consent or HID attachment. This coordinates cooperating app processes
and does not by itself establish cross-platform runtime validation.
