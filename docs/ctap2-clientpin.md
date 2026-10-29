# CTAP2 ClientPIN implementation boundary

ClientPIN is advertised only when its complete state and request path is available. A partially initialized PIN provider must return an error and must not set `clientPin` in GetInfo.

## PIN/UV Auth Protocol 1

The first implementation uses PIN/UV Auth Protocol 1 only, matching the advertised CTAP 2.0 profile:

- Generate a fresh P-256 key-agreement secret and return its COSE public key (EC2, P-256, x and y coordinates).
- Validate the peer point before ECDH. Derive the 32-byte shared secret as SHA-256 of the big-endian ECDH x-coordinate.
- Encrypt and decrypt with AES-256-CBC, a zero IV, and no padding. Accept only non-empty block-aligned ciphertext.
- Authenticate with the first 16 bytes of HMAC-SHA-256.
- Keep the PIN verifier as the first 16 bytes of SHA-256(PIN); never persist a plaintext PIN or PIN token.

PIN input is the decrypted 64-byte right-zero-padded value. Remove trailing zero bytes, require valid UTF-8, at least four Unicode code points, and at most 63 UTF-8 bytes. Retry state must be durable and protected with the same OS-backed credential protector. Invalid PIN attempts update that state before returning an error.

## Token and request authorization

PIN/UV auth tokens are random, in-memory secrets. They are scoped to the permissions and relying-party ID granted by the token request, expire on the protocol-defined lifecycle, and are discarded on service shutdown, reset, or replacement. MakeCredential and GetAssertion must verify the command's `pinUvAuthParam` over the 32-byte client data hash before setting the UV flag. An invalid or unpermitted token fails closed.

The local user approval path remains required for credential registration and assertion. PIN authentication supplies user verification; it does not silently authorize signing or bypass the existing user-presence prompt.

## Storage and reset

Persist only the PIN verifier and retry/block counters through authenticated, OS-protected storage. Include that state in CTAP Reset's atomic reset boundary so credentials cannot be erased while PIN state is left behind, or vice versa. A storage migration must preserve all existing credential records and reject unauthenticated or malformed state.

## Capability gate

GetInfo advertises `clientPin=true` and protocol `1` only after the protected PIN state provider, retry semantics, key agreement, encrypted PIN commands, token permission checks, and MakeCredential/GetAssertion UV integration are all active. Protocol 2, PIN change policy, credential management permissions, and other unimplemented features remain unadvertised.
