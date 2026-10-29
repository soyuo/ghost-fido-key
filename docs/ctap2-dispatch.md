# CTAP2 dispatch boundary

`ghost-fido-core` decodes CTAP2 command bytes and bounded CBOR once, retaining the parsed value with the request. `AuthenticatorService` consumes that value when it validates typed MakeCredential/GetAssertion fields, avoiding a second CBOR parse. GetInfo continues to validate its command payload, and typed request decoders remain available for direct callers. The service routes GetInfo, MakeCredential, GetAssertion, and GetNextAssertion through the existing provider-backed workflows. Provider and storage failures remain structured service errors for the transport/application layer to handle.

The service requires an explicit GetInfo profile, credential store, key store, user-confirmation provider, registration policy, and timeout. Its channel-aware entry point scopes multi-credential continuation state to the originating CTAPHID channel and clears it on any new command. `AuthenticatorHidSession` connects that service to `CtapHidSession`: it routes complete CBOR requests, frames CTAP2 results, and clears assertion state when a channel is cancelled or expires. The OS transport owner still reads and writes the returned fixed-size reports; native HID lifecycle remains separate.

CTAP2 Reset is accepted only with an empty payload during the first 10 seconds after the service starts (the HID runtime starts the service after attaching the device). It requires explicit local approval. On approval, the service deletes each referenced provider key before clearing credential metadata; a key deletion failure leaves metadata available for retry and never returns success. Reset does not yet reset other persistent authenticator state such as large-blob storage or future PIN/enterprise-attestation settings, which are not implemented by this profile.

Selected status wire values follow the FIDO CTAP 2.1 error table:

| Status | Wire value |
| --- | --- |
| `UserActionPending` | `0x23` |
| `UnsupportedOption` | `0x2B` |
| `NoCredentials` | `0x2E` |

See the [FIDO CTAP 2.1 status table](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#ctap2-error-codes).
