# CTAP2 GetAssertion request decoding

`GetAssertionRequest::decode` validates the bounded CBOR request map and extracts
the required RP ID, 32-byte client data hash, optional credential allow-list,
and the known `up`/`uv` boolean options.
Each allow-list descriptor must identify a non-empty credential ID of type
`public-key`. `rp_id_hash` computes SHA-256 over the UTF-8 RP ID, and
`find_credentials` selects matching records through the RP-isolated credential
store. An empty but present allow-list remains distinct from an absent list: it
matches no credentials and returns `NoCredentials`; it never selects
discoverable credentials. CTAP instructs platforms not to send empty allow-lists,
but this behavior follows the authenticator algorithm when one is received.
When the allow-list is absent, only discoverable credentials are selected.
Unknown option names are ignored and absent `up`/`uv` options remain
`None` for the execution layer to interpret. Decoding does not claim that the
authenticator can perform user verification. User approval and signing remain
follow-up work.

Unknown keys in the GetAssertion parameter and nested option/descriptor maps
are ignored as required by CTAP2 §8. Required fields, duplicate recognized
fields, and malformed values for recognized fields remain errors. The nested
`hmac-secret` input map is handled separately.

Schema failures expose a CTAP2 status through `GetAssertionError::status`:
malformed CBOR maps to `InvalidCbor`, missing fields to `MissingParameter`,
wrong types to `CborUnexpectedType`, and invalid values to `InvalidParameter`.
If a selected credential has no associated `CredRandom`, the request is still
authenticated and decrypted, but the extension output is omitted and the
assertion continues successfully, as required by CTAP 2.2 §12.7.

For the `hmac-secret` extension, `keyAgreement` must be a map. If the optional
`pinUvAuthProtocol` is present, it must be an unsigned integer; an absent value
continues to select protocol 1, while an unsupported unsigned value is an
`InvalidParameter`. Wrong-type values are rejected before key-agreement or
extension cryptography runs.
Absent top-level command parameters map to `MissingParameter`; missing required
descriptor members and wrong types map to `CborUnexpectedType`.

The required fields and allow-list shape follow the
[FIDO CTAP 2.1 authenticatorGetAssertion request](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorgetassertion-0x02).

`encode_get_assertion_response` serializes one successful response with the
credential descriptor, 37-byte authenticator data, and caller-provided
signature. Authenticator data contains the RP ID hash, UP flag, and supplied
signature counter; it does not assert UV or extensions. The user entity is
included only when a discoverable credential's user handle is supplied. The
encoder rejects empty or oversized credential IDs and signatures. It does not
perform approval, signing, or selection among multiple eligible credentials.

`execute_get_assertion` returns discoverable credentials newest first when the
allow-list is absent. For multiple matches, the first response includes
`numberOfCredentials`. The service retains remaining credential IDs and the
request in a continuation scoped to the CTAPHID channel; an empty-payload
`GetNextAssertion` signs and returns the next credential without asking for
approval again. Continuations expire 30 seconds after the initial response,
and missing, expired, or exhausted sequences return `NotAllowed`. Any other
command on that channel clears its continuation. Allow-list requests select a
matching credential without a continuation or `numberOfCredentials`.

Each response commits the next signature counter before it is returned. The
user entity is limited to the user handle when user verification was not
performed; stored name and display-name hints are not returned. The service's
`handle_on_channel` entry point must receive the originating CTAPHID channel for
independent concurrent continuation sequences. The legacy `handle` entry point
uses one reserved channel for callers without transport channel context.

## `largeBlobKey`

The request may include `largeBlobKey: true`; false or another value returns
`InvalidOption`. For a discoverable credential with a stored key, the CTAP
response includes the key as top-level integer field `0x07`. It is not encoded
in authenticator data. Older credentials without a stored key remain usable
and omit this response field. GetInfo advertises the extension only with
protected LargeBlobs storage; see [CTAP2 largeBlobKey](ctap2-largeblob-key.md).
