# Desktop approval flow

The desktop `UserVerification` provider publishes an `approval-request` Tauri
event containing a random one-time request ID, relying-party ID and optional
name, action, and timeout. The React UI renders the RP context as text and
requires the user to choose **Approve** or **Deny**. The UI returns that choice
through the `respond_approval` command.

Each pending ID maps to one response channel. The provider removes the ID when
it receives a decision or when its deadline expires, so unknown, replayed, and
late decisions are rejected. Denial returns `VerificationDecision::Rejected`;
expiry returns the platform timeout error. Failure to deliver an event or
receive a response fails closed. The event does not include credential IDs,
user handles, key references, or private key material.

This is the desktop approval boundary only. No native HID request source or
`AuthenticatorService` is connected to it yet, so the current app does not
receive browser authentication requests.
