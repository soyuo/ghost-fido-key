# Windows credential metadata protection

`WindowsCredentialProtector` implements the core `CredentialProtector` using
the current-user Windows Data Protection API. It uses `CRYPTPROTECT_UI_FORBIDDEN`
and does not request machine-wide protection. The associated data supplied by
the store is passed as DPAPI optional entropy, so unprotect fails if the schema
version's associated data does not match.

DPAPI output buffers are released with `LocalFree`; input and output sizes are
bounded to the credential store's 16 MiB payload limit plus bounded encryption
overhead. The API does not export an encryption key for application storage.

Data is normally decryptable only under the same user logon credentials and on
the same computer. A database copy by itself is therefore not a backup strategy;
users need an authenticated Windows profile recovery or a future explicit
credential migration flow. This provider protects metadata only. Private
credential keys remain the responsibility of `KeyStore`.
