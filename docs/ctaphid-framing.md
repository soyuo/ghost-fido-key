# CTAPHID framing boundary

`ghost-fido-core` owns transport-neutral 64-byte CTAPHID initialization and continuation framing. It validates non-zero channels, command bytes, payload limits, and continuation sequence numbers while leaving OS report I/O and CTAP command handling to later layers.
