# CTAP2 largeBlobKey extension

The authenticator supports the CTAP 2.2 `largeBlobKey` extension together with its protected `authenticatorLargeBlobs` array. GetInfo advertises `largeBlobKey` only while `largeBlobs=true` is available.

## MakeCredential

The extension input must be boolean `true`; other values return `CTAP2_ERR_INVALID_OPTION`. MakeCredential also requires `rk=true`. A new independent 32-byte key is generated for each successful discoverable credential and stored in the protected credential record. The successful CTAP response includes the key at integer map key `0x05`. It is never added to authenticator data or signed extension outputs.

## GetAssertion

The extension input must be boolean `true`; other values return `CTAP2_ERR_INVALID_OPTION`. If the selected discoverable credential has a stored key, the successful response includes it at integer map key `0x07`. Credentials created before this feature have no key and continue to work; no key is fabricated or derived for them.

## Storage and scope

The credential-record schema adds an optional 32-byte field and migrates older protected records without changing their credentials. Credential deletion and authenticator reset use the existing protected-store lifecycle, so deleting the record or resetting the store removes the key. Debug output redacts the secret and its in-memory wrapper zeroizes it on drop.

This implements the authenticator-side key extension. Browser-side blob compression, AES-GCM encryption/decryption, and large-blob entry management are platform-client responsibilities and are not performed by this extension handler.

Protocol behavior follows [CTAP 2.2 §12.3](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#section-12.3).
