# Credential metadata storage

`CredentialStore::default()` keeps records in memory. `CredentialStore::open`
opts into a versioned SQLite database and requires a `CredentialProtector`.
There is no plaintext persistence mode.

SQLite stores one protected payload containing the full credential record set.
Credential IDs, RP ID hashes, user handles, key references, key protection
metadata, discoverability, and signature counters are inside that payload.
The schema itself contains only a singleton key and a ciphertext blob. Private
key bytes are never part of a `CredentialRecord`.

The protector must provide authenticated encryption and authenticate the
associated data supplied by the store. Its encryption key must be managed
outside the SQLite database. The core crate defines this boundary but does not
provide an operating-system protector; callers must not open persistent storage
until a platform-backed protector is available.

Schema version 1 stores a single CBOR-encoded record set. New databases are
initialized transactionally. Unsupported schema versions, authentication
failures, malformed records, and SQLite errors fail closed. Record registration
and signature-counter updates commit the protected payload before changing the
in-memory view. The default in-memory store remains available for volatile use.

The encrypted payload is rewritten as one unit after each mutation. This keeps
identifiers and other metadata out of SQLite indexes and columns, while setting
a bounded maximum of 4,096 stored records and 16 MiB of serialized metadata.
