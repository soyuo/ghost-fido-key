# CTAP2 hmac-secret extension

The `hmac-secret` extension is advertised only when the protected credential
store and both registration and assertion paths can process it. The extension
uses credential-scoped random material stored inside the authenticated,
encrypted credential database. Neither the signing key provider nor the UI
receives this material.

The implementation target is CTAP 2.1 Protocol 1 processing: P-256 key
agreement, SHA-256 key derivation, authenticated encrypted one- or two-salt
input, and encrypted HMAC-SHA-256 output. Both UV and non-UV credential randoms
are retained so assertions select material according to the final verified UV
flag. Legacy credentials without random material remain usable for ordinary
assertions, while the extension is omitted for those credentials.

`FIDO_2_1` remains unadvertised until every mandatory CTAP 2.1 feature is
implemented. In particular, PIN-based UV also requires `credProtect`; this
document does not claim CTAP 2.1 conformance or browser interoperability.
