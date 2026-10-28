# CTAP2 dispatch boundary

`ghost-fido-core` now decodes the CTAP2 command byte and encodes the status-prefixed response envelope. The boundary intentionally does not parse CBOR or implement credentials; those capabilities remain later stages and must report explicit CTAP errors until available.
