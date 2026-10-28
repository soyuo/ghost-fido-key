# CTAP2 dispatch boundary

`ghost-fido-core` decodes CTAP2 command bytes, validates bounded CBOR, serves an explicitly configured GetInfo profile, and validates typed MakeCredential/GetAssertion requests. `ghost-platform::AuthenticatorService` routes GetInfo, MakeCredential, and GetAssertion through the existing provider-backed workflows. Provider and storage failures remain structured service errors for the transport/application layer to handle.

The service requires an explicit GetInfo profile, credential store, key store, user-confirmation provider, registration policy, and timeout. It returns `InvalidCommand` for unsupported commands. CTAPHID framing and native HID lifecycle remain separate. Credential selection currently supports one unambiguous GetAssertion match; multiple matches are denied until a chooser and GetNextAssertion flow exist.

Selected status wire values follow the FIDO CTAP 2.1 error table:

| Status | Wire value |
| --- | --- |
| `UserActionPending` | `0x23` |
| `UnsupportedOption` | `0x2B` |
| `NoCredentials` | `0x2E` |

See the [FIDO CTAP 2.1 status table](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#ctap2-error-codes).
