# Linux signing-key storage

`LinuxKeyStore` is a software-key fallback, not a TPM provider. The
`PlatformProtectedOnly` policy always fails closed while no hardware-backed
provider is available. Software key creation requires both
`SoftwareKeyAfterExplicitConsent` and a `SoftwareKeyConsent` token.

The provider generates a P-256 scalar, stores it as a Secret Service item in
the default collection, and returns only an opaque item reference and public
coordinates. Signing loads the matching single item, unlocks it when required,
and returns a fixed-width P1363 ES256 signature. Duplicate, missing, malformed,
foreign, locked, or unavailable items fail closed. Deletion removes the item.

These keys are reported as software-backed and exportable: the application can
retrieve the scalar to perform signing. This is a lower protection level than a
TPM-backed non-exportable key. The credential database and Secret Service item
must both remain available to recover a credential. Removing or replacing the
Secret Service collection can make its credentials unusable. The desktop UI
does not yet offer the software-key consent setting, so the provider cannot be
selected by the current desktop flow.
