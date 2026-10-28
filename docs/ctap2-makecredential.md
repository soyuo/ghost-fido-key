# CTAP2 MakeCredential request decoding

`MakeCredentialRequest::decode` validates the required client data hash, RP and
user entities, and ordered public key credential parameters. User handles are
limited to 1–64 bytes as required by [WebAuthn](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentity-id).
It also decodes
the optional credential exclusion list and `rk`, `uv`, and `up` options. Schema
failures map to CTAP2 invalid-CBOR, missing-parameter, unexpected-type, or
invalid-parameter statuses.

This boundary performs no user interaction, key creation, persistence,
attestation, or signing. The algorithm list is preserved in platform order and
duplicate entries are rejected; deciding which algorithms this authenticator
can actually create belongs to the cryptographic provider.

The request field identifiers and required fields follow the
[FIDO CTAP 2.1 authenticatorMakeCredential request](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatormakecredential-0x01).
