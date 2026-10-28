# Protected key provider public keys

`KeyStore::create_signing_key` returns a `CreatedSigningKey` containing an
opaque key reference, protection metadata, and the matching ES256 public
coordinates. The private key remains inside the provider. The CTAP2 core can
encode the public coordinates as a COSE EC2 key without seeing private key
material.

The Windows TPM provider exports only `BCRYPT_ECCPUBLIC_BLOB` after finalizing
the new CNG key. It validates the ECDSA P-256 magic, blob size, and 32-byte
coordinate size before returning the point. CNG stores X and Y as big-endian
unsigned values in the public blob, as described by Microsoft's
[`BCRYPT_ECCKEY_BLOB` documentation](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob).

macOS and unavailable providers still fail closed until their native key
bridges exist. No private-key blob export or software-key fallback is added.
