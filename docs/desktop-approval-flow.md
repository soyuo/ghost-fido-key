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

## Session-lock behavior

The desktop checks session protection before starting the authenticator and
before delivering an approval. A lock cancels pending requests on Windows and
Linux; the UI removes each prompt through `approval-cancelled`. Unlocking does
not restore a canceled request. The 30-second approval deadline remains a
fail-closed fallback.

- **Windows:** the app registers for this login session's WTS lock/unlock
  notifications and checks whether the active desktop is locked. A lock
  cancels pending approvals and blocks new ones. If the monitor cannot be
  installed or the lock state cannot be checked, authentication fails closed.
- **Linux:** the app monitors the current systemd-logind session's `Lock` and
  `Unlock` signals and re-reads `LockedHint`. A `Lock` signal cancels pending
  approvals. `Unlock` alone does not resume them; authentication remains
  blocked until the next check confirms `LockedHint` is false. Missing or
  unavailable logind protection fails closed. Behavior depends on the desktop
  environment delivering the expected signal and lock hint.
- **macOS:** an observed user-session switch-out invalidates pending approval
  during the runtime's polling interval. This detects session switch-out, not
  screen locking; no screen-lock detection is claimed. The 30-second deadline
  remains the fallback when no session-switch notification is observed.

These runtime paths still require target-machine acceptance. Follow the T-022
procedure in [`security-acceptance.md`](security-acceptance.md), retain the
relying-party result, and leave each platform row unverified until its required
cases pass. This documentation does not establish OS or browser support.

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
