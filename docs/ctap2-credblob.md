# CTAP2 `credBlob`

This document describes authenticator-side support for the CTAP 2.2 `credBlob`
extension. The authenticator treats the value as opaque application data; it
does not interpret or transform its contents.

## Feature detection

GetInfo advertises the `credBlob` extension and `maxCredBlobLength` (key
`0x0f`, value 32) only while protected credential storage is available.
`credProtect` is advertised at the same time, as required for `credBlob`
support. The implementation stores blobs only with discoverable credentials.

## MakeCredential

The CTAP `credBlob` input is a byte string. Values up to 32 bytes are stored in
the encrypted credential record when the credential is discoverable. The
signed authenticator-data extension reports `credBlob: true` if storage
succeeded, and `false` if the value exceeds the advertised capacity or the
credential is not discoverable. No value is stored when the extension is
absent.

## GetAssertion

The CTAP `credBlob` input is a boolean request. When true, the authenticator
returns the selected discoverable credential's stored bytes in the signed
authenticator-data `credBlob` extension. If that credential has no value, it
returns an empty byte string. The extension is omitted when it was not
requested.

Credential records use schema version 9 and store the value only inside the
existing protected credential payload. Earlier record layouts remain readable
and have no blob. Credential deletion and reset follow the existing encrypted
record lifecycle. The blob is redacted from debug output and temporary
credential/CBOR buffers are zeroized.

The authenticator does not compress, encrypt, or interpret the opaque value on
behalf of a relying party; those client-side operations are outside this
extension's authenticator-side storage behavior.

See the [CTAP 2.2 `credBlob` specification, section 12.2](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#section-12.2).
