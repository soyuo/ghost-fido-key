# CTAP2 GetAssertion request decoding

`GetAssertionRequest::decode` validates the bounded CBOR request map and extracts
the required RP ID, 32-byte client data hash, and optional credential allow-list.
Each allow-list descriptor must identify a non-empty credential ID of type
`public-key`. `rp_id_hash` computes SHA-256 over the UTF-8 RP ID, and
`find_credentials` selects matching records through the RP-isolated credential
store. When the allow-list is absent, only discoverable credentials are
selected. User approval, signing, and assertion encoding remain follow-up work.

Schema failures expose a CTAP2 status through `GetAssertionError::status`:
malformed CBOR maps to `InvalidCbor`, missing fields to `MissingParameter`,
wrong types to `CborUnexpectedType`, and invalid values to `InvalidParameter`.

The required fields and allow-list shape follow the
[FIDO CTAP 2.1 authenticatorGetAssertion request](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorgetassertion-0x02).
