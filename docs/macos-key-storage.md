# macOS signing-key storage

`MacOsKeyStore` requests persistent P-256 signing keys in the Data Protection
Keychain. The default `PlatformProtectedOnly` policy asks Security.framework for
a Secure Enclave key first. If CryptoKit reports that the device does not
support Secure Enclave access, the authenticator asks for separate,
per-credential software-key consent. A denial or cancellation creates no key.
If Secure Enclave access is reported as available, key-creation errors do not
trigger fallback. See Apple's [`SecureEnclave.isAvailable`](https://developer.apple.com/documentation/cryptokit/secureenclave/isavailable).

Software-backed Security.framework keys are created only after the distinct
fallback approval and with both `SoftwareKeyAfterExplicitConsent` and a
`SoftwareKeyConsent` value. Their protection metadata identifies them as
software keys and exportable. This is a lower protection level and the
credential remains identifiable as such in the credential list.

The database stores only an opaque Security.framework label reference. Public
coordinates are returned separately; signing uses the stored key handle and
returns fixed-width P1363 signatures. Key deletion removes the corresponding
Security.framework item. The private key is not exported or placed in SQLite.

Secure Enclave keys require a compatible Mac and use the Data Protection
Keychain. Access after signing, entitlement, or application identity changes
must be verified with the packaged app. A credential database by itself cannot
restore its signing keys. See Apple's [TN3137 on macOS Keychain APIs](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains).
