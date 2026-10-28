# CTAP2 dispatch boundary

`ghost-fido-core` decodes CTAP2 command bytes, validates bounded CBOR, serves an explicitly configured GetInfo profile, and validates GetAssertion request fields. Credential lookup, user approval, signing, and the remaining CTAP commands are not implemented yet.

Selected status wire values follow the FIDO CTAP 2.1 error table:

| Status | Wire value |
| --- | --- |
| `UserActionPending` | `0x23` |
| `UnsupportedOption` | `0x2B` |
| `NoCredentials` | `0x2E` |

See the [FIDO CTAP 2.1 status table](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#ctap2-error-codes).
