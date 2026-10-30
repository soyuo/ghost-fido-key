# CTAP2 LargeBlobs

The authenticator implements the CTAP 2.2 `authenticatorLargeBlobs` command (`0x0c`) for the shared serialized large-blob array. It reports `largeBlobs=true`, `maxSerializedLargeBlobArray=65536`, and the `largeBlobKey` extension in GetInfo only when the protected SQLite store is available and reset is not in progress.

For discoverable credentials, the `largeBlobKey` extension stores a fresh 32-byte secret in that credential's protected record. MakeCredential accepts the extension only with `rk=true` and returns the key as CTAP response field `0x05`; GetAssertion returns a stored key only when requested, as response field `0x07`. The key is not included in authenticator data. See [CTAP2 largeBlobKey](ctap2-largeblob-key.md) for request validation, migration, and response details.

The array is stored in its own authenticated, encrypted SQLite row. A new store starts with the CTAP-defined empty CBOR array and its 16-byte SHA-256 prefix. Reads return bounded fragments. Writes assemble sequential fragments in volatile per-channel state and replace the protected row atomically only after the declared length and final digest validate. Incomplete, expired, cancelled, or invalid writes never change the durable array. The authenticator treats the array content as opaque and does not parse or modify its entries.

Each fragment is limited to `maxMsgSize - 64` bytes. Get requests require an offset and return up to the requested number of bytes; an offset equal to the array length returns an empty fragment. Set starts at offset zero with a total length, then requires consecutive offsets without another length. The serialized array must be at least 17 bytes, no larger than the advertised capacity, and end in the first 16 bytes of SHA-256 over the preceding CBOR array bytes.

When PIN/UV is configured or `alwaysUv` is enabled, every set fragment requires a protocol-matched `pinUvAuthParam` and a token with the `lbw` permission. The authentication message is `0xff` repeated 32 times, followed by `0c00`, the little-endian 32-bit fragment offset, and SHA-256 of the fragment. Read requests do not accept PIN/UV authorization fields.

Authenticator reset restores the initial empty array in the same protected reset transaction that clears credentials and PIN state. A stored array with an invalid digest or serialized length is treated as that initial array. See the [CTAP 2.2 specification, section 6.10](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#section-6.10).
