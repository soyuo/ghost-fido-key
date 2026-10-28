# CTAP2 GetAssertion request decoding

`GetAssertionRequest::decode` validates the bounded CBOR request map and extracts
the required RP ID, 32-byte client data hash, optional credential allow-list,
and the known `up`/`uv` boolean options.
Each allow-list descriptor must identify a non-empty credential ID of type
`public-key`. `rp_id_hash` computes SHA-256 over the UTF-8 RP ID, and
`find_credentials` selects matching records through the RP-isolated credential
store. When the allow-list is absent, only discoverable credentials are
selected. Unknown option names are ignored and absent `up`/`uv` options remain
`None` for the execution layer to interpret. Decoding does not claim that the
authenticator can perform user verification. User approval and signing remain
follow-up work.

Schema failures expose a CTAP2 status through `GetAssertionError::status`:
malformed CBOR maps to `InvalidCbor`, missing fields to `MissingParameter`,
wrong types to `CborUnexpectedType`, and invalid values to `InvalidParameter`.

The required fields and allow-list shape follow the
[FIDO CTAP 2.1 authenticatorGetAssertion request](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorgetassertion-0x02).

`encode_get_assertion_response` serializes one successful response with the
credential descriptor, 37-byte authenticator data, and caller-provided
signature. Authenticator data contains the RP ID hash, UP flag, and supplied
signature counter; it does not assert UV or extensions. The user entity is
included only when a discoverable credential's user handle is supplied. The
encoder rejects empty or oversized credential IDs and signatures. It does not
perform approval, signing, or selection among multiple eligible credentials.

`execute_get_assertion` currently supports exactly one matching credential. It
rejects requests that disable UP or require unavailable UV, requests explicit
local approval before signing, hashes `authenticatorData || clientDataHash`,
converts the provider's fixed-width ES256 signature to DER, and commits the next
signature counter before returning the encoded response. Ambiguous matches fail
closed until a credential chooser and GetNextAssertion flow are implemented.
