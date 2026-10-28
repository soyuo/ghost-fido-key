# CTAPHID INIT channel allocation

The allocator accepts an 8-byte nonce, allocates a nonzero unicast channel,
and returns the 17-byte CTAPHID_INIT response payload with the nonce echoed.
The response advertises protocol version 2.1.0 and no optional capabilities.
The caller supplies the timeout; expired channels are reclaimed when the next
allocation runs or when `expire(now)` is called. Exhausted channel capacity and
invalid nonce length are distinct errors.
