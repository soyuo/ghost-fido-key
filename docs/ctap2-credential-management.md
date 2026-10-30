# CTAP2 Credential Management boundary

Credential Management is a separate CTAP2 surface from the desktop credential manager. Advertise `credMgmt` only when the complete protected metadata, token authorization, and deletion paths are operational.

The `credMgmt` GetInfo option is enabled only while PIN is set and each discoverable record has an RP ID and an ES256 public key. Newly registered credentials persist the public key. Legacy records backfill it through their platform key provider; records with unrecoverable RP IDs or keys keep the option disabled. Responses include only supported fields and omit `credProtect` and `largeBlobKey`.

## Initial CTAP 2.1 scope

Implement CTAP Credential Management subcommands 1 through 7: credential metadata, RP enumeration, credential enumeration, credential deletion, and user name/display-name updates. Expose discoverable credentials only. RP enumeration must include the RP ID; optional RP fields may be omitted. Credential enumeration returns the stored user entity, descriptor, and ES256 public key. Omit optional extensions that are not implemented.

Every command requires a valid PIN/UV auth token with the Credential Management permission (`cm`, bit `0x04`). HMAC authentication binds the subcommand byte and the encoded subcommand parameters. Metadata and RP enumeration require an unscoped token. Per-RP enumeration, delete, and update must enforce a token's optional RP ID scope. Enumeration state is bounded, per CTAPHID channel, expires, and is discarded on cancellation/reset.

Credential deletion persists an authenticated intent before deleting the platform key. If key deletion fails, keep the credential and intent. After key deletion succeeds, remove the credential and intent in one SQLite transaction. Resume pending deletion before CTAP commands and desktop credential-management operations; keep the authenticator fail-closed if recovery cannot complete. The intent stores only protected credential and provider references and is never exposed to protocol responses or UI.

Deletion removes the provider key before committing metadata removal. A failed key deletion must leave metadata intact. User information updates may change only `name` and `displayName`; the supplied `id` must equal the stored handle and is immutable. A missing or empty label removes that stored field, so an update containing only `id` clears both labels.

## Protected metadata and migration

Credential-management metadata remains in the existing authenticated-encrypted credential store. Persist the public ES256 key with each record. For records created before that field existed, recover the public key through the owning platform key provider and persist it before returning enumeration data. Fail the operation if key recovery or protected persistence fails; never return fabricated public-key material. Keep legacy credential ciphertext readable and migrate additively.

## Capability gate

Do not advertise `credMgmt` until all seven subcommands, permission/RP-scope checks, discoverable-only enumeration, old-record public-key recovery, durable updates, restart-safe credential deletion, and cancellation/reset cleanup are active. Browser interoperability remains a separate validation gate.
