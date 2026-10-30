# Linux signing-key storage

`LinuxKeyStore` is a software-key fallback, not a TPM provider. The
`PlatformProtectedOnly` policy always fails closed while no hardware-backed
provider is available. Software key creation requires both
`SoftwareKeyAfterExplicitConsent` and a `SoftwareKeyConsent` token.

The provider generates a P-256 scalar, stores it as a Secret Service item in
the default collection through a synchronous libdbus client, and returns only
an opaque item reference and public coordinates. Signing loads the matching
single item, unlocks it when required, and returns a fixed-width P1363 ES256
signature. Duplicate, missing, malformed, foreign, locked, or unavailable
items fail closed. Deletion removes the item. Existing items keep their label,
attributes, UUID references, and encrypted Secret Service payload; changing the
Rust D-Bus client does not rewrite or delete them.

Linux builds require the `libdbus-1-dev` development package. Debian bundles
declare `libdbus-1-3` as a runtime dependency; other distribution packages must
provide the matching libdbus runtime.

These keys are reported as software-backed and exportable: the application can
retrieve the scalar to perform signing. This is a lower protection level than a
TPM-backed non-exportable key. The credential database and Secret Service item
must both remain available to recover a credential. Removing or replacing the
Secret Service collection can make its credentials unusable.

## Desktop consent

On Linux, starting the authenticator opens a native warning about software-key
storage. The Rust start command creates a consent token scoped to that runtime
session only after the user accepts the warning. Canceling or closing the dialog
keeps the runtime stopped, so no software key can be created through that
attempt. Consent is requested again on a later start; it is not a persistent
setting. Windows and macOS use platform-protected key policies and do not offer
this software-key fallback flow.

This consent flow only authorizes software-backed signing keys. It does not
establish browser interoperability, OS-protected key storage, or support for a
particular Linux distribution or desktop session.
