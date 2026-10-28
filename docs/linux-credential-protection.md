# Linux credential metadata protection

`LinuxCredentialProtector` stores a random 256-bit encryption key in the
default [Secret Service collection](https://specifications.freedesktop.org/secret-service/latest/ch03.html)
using stable application and purpose attributes. It uses an encrypted D-Bus
session through the Rust [`secret-service` blocking API](https://docs.rs/secret-service/5.1.0/secret_service/blocking/index.html)
and AES-256-GCM for the SQLite payload. The supplied schema associated data,
plus a provider-specific context prefix, is authenticated as AEAD additional
data. Each ciphertext has a version byte and a fresh 96-bit nonce.

The provider requires a running Secret Service implementation such as GNOME
Keyring or KWallet and an accessible default collection. Locked items may
require the keyring's unlock interaction. No file-based or plaintext fallback
is used. Missing or duplicate key items, denied unlocks, malformed envelopes,
and authentication failures all fail closed.

The key is recoverable only through the same user's keyring. Copying the SQLite
database without the corresponding Secret Service collection is not a backup
or migration strategy. `CredentialStore::open` is not yet initialized by the
desktop app; macOS metadata protection also remains to be implemented.
