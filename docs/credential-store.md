# Credential metadata storage

`CredentialStore::default()` keeps records in memory. `CredentialStore::open`
opts into a versioned SQLite database and requires a `CredentialProtector`.
There is no plaintext persistence mode.

SQLite stores credential records and PIN state in separate protected payloads.
Credential IDs, RP ID hashes, user handles, key references, key protection
metadata, discoverability, and signature counters are inside the credential
payload. The PIN verifier and retry state are in the separate PIN payload.
Both tables contain only a singleton key and ciphertext blob. Private key bytes
are never part of a `CredentialRecord`.

The protector must provide authenticated encryption and authenticate the
associated data supplied by the store. Its encryption key must be managed
outside the SQLite database. `WindowsCredentialProtector` uses current-user
DPAPI and supplies the associated data as DPAPI optional entropy. The resulting
data is bound to the Windows user profile and normally to the computer; moving
the database alone is not a supported recovery method. On Linux,
`LinuxCredentialProtector` stores one random key in the default Secret Service
collection and encrypts metadata with AES-256-GCM. It fails closed when Secret
Service is unavailable, the key cannot be unlocked, or duplicate key items are
found. On macOS, `MacOsCredentialProtector` stores its random key in the
default Keychain and uses the same bounded AES-256-GCM envelope with a
macOS-specific associated-data prefix. It fails closed when the Keychain item
cannot be read or created. The Tauri desktop app creates its application data
directory and opens `credentials.sqlite3` there at startup. It keeps the store
for the application lifetime and reports initialization status to the UI. If
the directory or OS protection provider is unavailable, the app remains open
but protected storage is unavailable; it never substitutes an in-memory or
plaintext store. The SQLite file alone is not a backup: Windows recovery depends
on the original user profile, Linux on the same Secret Service key item, and
macOS on access to the same default Keychain item.

SQLite `user_version` 10 tracks the current complete store format. The credential
record payload has its own CBOR schema version 7; these are distinct version
counters because PIN state is stored separately. SQLite stores with `user_version`
1–3 are read using their original associated data, validated, assigned a
deterministic legacy creation order where needed, and resealed using the current
credential payload format. Versions 4–10 are decoded using their corresponding
credential payload schema. Version 9 added an encrypted reset journal containing
provider key references still awaiting deletion. Version 10 adds a nonsecret
metadata-key cleanup marker to that journal. After provider signing keys are
deleted, reset commits empty credential/PIN payloads and the marker before
removing the app-managed metadata key. Linux Secret Service and macOS Keychain
deletion is idempotent; startup checks the marker before decrypting old payloads,
and recovery never loads or creates a key before retrying deletion. After key
deletion succeeds, reset drops the encrypted tables and marker in one transaction
and returns the database to an empty schema; a new metadata key is created only
when the store is next opened or written. Windows uses OS-managed DPAPI master
keys and does not remove them. While either reset phase is pending, the store
hides credential and PIN state and rejects normal updates. CTAP and desktop reset
paths resume cleanup before normal use; each completed provider deletion is
checkpointed so a restart can safely retry cleanup. Missing PIN state in a store
older than version 8 is initialized as protected default state. Unsupported
versions, authentication failures, malformed records, and SQLite errors fail
closed. Record registration
and signature-counter updates persist the protected record payload before
changing the in-memory view. The default in-memory store remains available for
volatile use.

User labels are presentation hints only; they are not credential identifiers or
authentication inputs. `Debug` output redacts them. Each optional label is
limited to 256 UTF-8 bytes.

The encrypted payload is rewritten as one unit after each mutation. This keeps
identifiers and other metadata out of SQLite indexes and columns, while setting
a bounded maximum of 4,096 stored records and 16 MiB of serialized metadata.
