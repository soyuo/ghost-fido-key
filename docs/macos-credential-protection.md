# macOS credential metadata protection

`MacOsCredentialProtector` keeps a random 256-bit metadata-encryption key in
the user's default macOS Keychain. The key is created as a generic password
item. Creation uses Keychain's atomic add operation; if another process creates
the item concurrently, the provider reloads the existing item. It does not
replace an existing key. Keychain lookup, access, or decoding failures stop
store access rather than falling back to plaintext or another key.

Credential metadata uses the shared bounded AES-256-GCM envelope. Each write
uses a fresh 96-bit nonce, and authenticated data combines the macOS provider
prefix with the SQLite schema version data supplied by the store. This keeps
the Linux and macOS cryptographic format shared while preventing ciphertext
from being moved between platform providers or schema versions.

The key is not stored in SQLite or beside the database. The database can only
be reopened when the matching item remains accessible in the same user's
default Keychain. Keychain access identity and application signing may affect
access after packaging, so the desktop application must initialize the
persistent store with this provider and surface Keychain failures clearly.
