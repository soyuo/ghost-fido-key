# CTAP2 MakeCredential request decoding

`MakeCredentialRequest::decode` validates the required client data hash, RP and
user entities, and ordered public key credential parameters. User handles are
limited to 1–64 bytes as required by [WebAuthn](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentity-id).
It also decodes
the optional credential exclusion list and `rk`, `uv`, and `up` options. Schema
failures map to CTAP2 invalid-CBOR, missing-parameter, unexpected-type, or
invalid-parameter statuses.

Request decoding performs no user interaction, key creation, persistence,
attestation, or signing. The algorithm list is preserved in platform order and
duplicate entries are rejected; deciding which algorithms this authenticator
can actually create belongs to the cryptographic provider.

The platform's `check_credential_exclusion` checks excludeList IDs against the
requested RP hash. If an existing credential matches, it asks the local
`UserVerification` provider for a distinct `CredentialExclusionCheck` presence
interaction before returning `CredentialExcluded`. A completed interaction or
provider timeout yields that protocol response; provider errors fail closed
without revealing whether the credential matched. The prompt receives the RP
ID and optional RP name, but never the matching credential ID.
This behavior follows CTAP 2.1's `excludeList` processing rules in
[authenticatorMakeCredential](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatormakecredential-0x01).

The request field identifiers and required fields follow the
[FIDO CTAP 2.1 authenticatorMakeCredential request](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatormakecredential-0x01).

`encode_make_credential_response` builds a `fmt: none` CBOR response. Its
authenticator data contains the RP hash, UP/AT flags, a zero sign counter, the
AAGUID, credential ID, and ES256 COSE public key. It can set UV only when the
caller has established user verification. IDs must contain 1–1023 bytes. This
response is not an attestation of hardware provenance.

`ghost-platform::register_make_credential` checks for an offered ES256
algorithm, runs the RP-scoped exclusion check, waits for explicit local
registration approval, then creates the protected key and stores its opaque
reference and protection metadata. It returns protocol errors for unsupported
options, user rejection, and timeout. If record insertion fails after key
creation, it deletes the new key. The caller owns the in-memory credential
store; persistence is still required before credentials survive app restart.

Credential IDs, RP hashes, user handles, and provider key references are
redacted from credential `Debug` output.
