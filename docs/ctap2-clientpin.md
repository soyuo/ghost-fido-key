# CTAP2 ClientPIN and PIN/UV Auth Protocols

ClientPIN is advertised only when its protected state and request path are available. A partially initialized PIN provider returns an error and must not set `clientPin` in GetInfo.

## Protocol compatibility

The authenticator accepts PIN/UV Auth Protocol 1 and 2 and advertises them in descending preference order (`[2, 1]`) when protected credential storage is available. An omitted protocol identifier selects Protocol 1 for compatibility. An explicitly malformed or unsupported identifier returns `InvalidParameter`; it never silently falls back to Protocol 1. Key-agreement exchanges and PIN/UV tokens are bound to the selected protocol, and command authorization rejects a protocol mismatch.

Protocol 1 preserves the CTAP2.0 behavior:

- Generate a fresh P-256 key-agreement secret and return its COSE public key (EC2, P-256, x and y coordinates).
- Validate the peer point before ECDH. Derive the 32-byte shared secret as SHA-256 of the big-endian ECDH x-coordinate.
- Encrypt and decrypt with AES-256-CBC, a zero IV, and no padding. Accept only non-empty block-aligned ciphertext.
- Authenticate with the first 16 bytes of HMAC-SHA-256.

Protocol 2 follows CTAP2.1/2.2 §6.5.7:

- Derive two separate 32-byte HKDF-SHA-256 outputs from the ECDH x-coordinate, using a 32-byte zero salt and the info strings `CTAP2 HMAC key` and `CTAP2 AES key`. Concatenate the outputs; they must not be derived as one 64-byte HKDF expansion.
- Use the first half for HMAC-SHA-256 and the second half for AES-256-CBC.
- Prefix encrypted data with a fresh random 16-byte IV; do not add padding. Reject malformed ciphertext lengths.
- Use the full 32-byte HMAC-SHA-256 result and a 32-byte `pinUvAuthToken`.

Both protocols keep the PIN verifier as the first 16 bytes of SHA-256(PIN); plaintext PINs and tokens are never persisted. PIN input is the decrypted 64-byte right-zero-padded value. Remove trailing zero bytes, require valid UTF-8, at least four Unicode code points, and at most 63 UTF-8 bytes. Retry state must be durable and protected with the same OS-backed credential protector. Invalid current-PIN attempts consume a retry before returning an error; a correct current PIN during `changePIN` restores the retry count before the replacement PIN is decrypted and validated.

## Token and request authorization

PIN/UV auth tokens are random, in-memory secrets. Legacy `getPINToken` grants only MakeCredential and GetAssertion. `getPINUvAuthTokenUsingPinWithPermissions` supports MakeCredential (`0x01`), GetAssertion (`0x02`), and Credential Management (`0x04`) and may bind the token to one RP ID. A zero permissions value is invalid; defined permissions that this authenticator does not support are rejected, while undefined permission bits are ignored. The active token is bound to the CTAPHID channel and protocol used to issue it, and expires after 30 seconds. Successfully issuing a new token invalidates every previously issued token across all channels and supported protocols, as required by CTAP. Tokens are also discarded on channel cancellation, service shutdown, or reset. MakeCredential and GetAssertion verify the command's `pinUvAuthParam` over the 32-byte client data hash before setting the UV flag. An invalid, mismatched, or unpermitted token fails closed.

The `hmac-secret` extension also records its selected PIN/UV protocol and validates its protocol-specific authentication length and encrypted salt size. Its key agreement must use the same protocol selected in the extension request.

The local user approval path remains required for credential registration and assertion. PIN authentication supplies user verification; it does not silently authorize signing or bypass the existing user-presence prompt. Credential Management uses the separate `cm` permission (`0x04`) and is granted only by the permission-based token subcommand; legacy `getPINToken` never grants it.

## Storage, reset, and GetInfo

Persist only the PIN verifier and retry counter through authenticated, OS-protected storage. Keep it in a separate encrypted SQLite row with its own associated-data label; leave the existing credential-record ciphertext and format intact. Upgrade the store version only in the same transaction that inserts the initial protected PIN state. Include both ciphertext updates in CTAP Reset's atomic transaction so credentials cannot be erased while PIN state is left behind, or vice versa. Reject unauthenticated or malformed state.

GetInfo exposes `pinUvAuthToken` and Protocol 2 only when protected storage is available. `FIDO_2_1` is added only when its mandatory feature requirements are met: discoverable credentials are enabled, ClientPIN is configured, credential management and both `hmac-secret` and `credProtect` are available, the `pinUvAuthToken` option is true, and Protocol 2 is advertised. Otherwise the profile stays at `FIDO_2_0`. This implementation does not claim CTAP2.2 support.
