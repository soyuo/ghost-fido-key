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

The macOS provider creates a persistent P-256 key in the Data Protection
Keychain. `PlatformProtectedOnly` requests a Secure Enclave token and fails
closed if the enclave cannot create the key. Software-backed Security.framework
keys require both the software-key policy and its explicit consent token; their
metadata reports `Software` and `exportable: true`. Private keys are never
exported by the provider. Public coordinates are validated from the uncompressed
X9.63 public point, while signatures are converted from strict ASN.1 DER to the
64-byte P1363 form used by the authenticator.

Secure Enclave key access depends on the Data Protection Keychain and the
application's signing identity and entitlements. A database backup does not
include the key. See Apple's [TN3137 on macOS Keychain APIs](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains).
