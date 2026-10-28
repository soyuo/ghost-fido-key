# Credential domain isolation

The core credential store keeps only an opaque key handle; private key bytes
remain the responsibility of the platform key provider. Every lookup requires
an exact RP ID hash. Allow-list selection and discoverable selection are both
filtered by that hash, so an identifier from another RP cannot disclose a
credential. Registration rejects duplicate identifiers and empty metadata.
