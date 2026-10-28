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
outside the SQLite database. `WindowsCredentialProtector` uses current-user
DPAPI and supplies the associated data as DPAPI optional entropy. The resulting
data is bound to the Windows user profile and normally to the computer; moving
the database alone is not a supported recovery method. On Linux,
`LinuxCredentialProtector` stores one random key in the default Secret Service
collection and encrypts metadata with AES-256-GCM. It fails closed when Secret
Service is unavailable, the key cannot be unlocked, or duplicate key items are
found. macOS protection remains unavailable, and the desktop app does not yet
open this persistent store automatically.

Schema version 3 stores a single CBOR-encoded record set, including optional
user name and display name hints and the store-assigned credential creation
order. New databases are initialized transactionally. Opening a version 1 or 2
database authenticates it with its original associated data, validates the
records, assigns legacy records a deterministic order by credential ID, seals
the v3 payload with v3 associated data, and commits the payload and schema
version together. A failed migration leaves the original database intact. An
older binary rejects a v3 database without modifying it. Unsupported schema
versions, authentication failures, malformed records, and SQLite errors fail
closed. Record registration and signature-counter updates commit the v3
protected payload before changing the in-memory view. The default in-memory
store remains available for volatile use.

User labels are presentation hints only; they are not credential identifiers or
authentication inputs. `Debug` output redacts them. Each optional label is
limited to 256 UTF-8 bytes.

The encrypted payload is rewritten as one unit after each mutation. This keeps
identifiers and other metadata out of SQLite indexes and columns, while setting
a bounded maximum of 4,096 stored records and 16 MiB of serialized metadata.
