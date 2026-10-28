# Desktop approval flow

The desktop `UserVerification` provider publishes an `approval-request` Tauri
event containing a random one-time request ID, relying-party ID and optional
name, action, and timeout. The React UI renders the RP context as text and
requires the user to choose **Approve** or **Deny**. The UI returns that choice
through the `respond_approval` command.

Each pending ID maps to one response channel. The provider removes the ID when
it receives a decision or when its deadline expires, so unknown, replayed, and
late decisions are rejected. Denial returns `VerificationDecision::Rejected`;
expiry returns the platform timeout error. A matching CTAPHID CANCEL sends
`VerificationDecision::Cancelled`, emits `approval-cancelled`, and clears the
UI prompt. Cancellation maps to CTAP2 `KEEPALIVE_CANCEL`. Failure to deliver an
event or receive a response fails closed. The event does not include credential
IDs, user handles, key references, or private key material.

This is the desktop approval boundary only. The Tauri app still has no live HID
request source, so it does not receive browser authentication requests.