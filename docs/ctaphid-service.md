# CTAPHID authenticator service adapter

`AuthenticatorHidSession` owns transport-neutral `CtapHidSession` state. The
transport owner passes each complete 64-byte output report to `receive_report`
with a monotonic timestamp. It returns expired channel IDs alongside the core
`SessionEvent`, so the caller can clear channel-scoped service state while
initialization, ping, error, and CTAP2 response reports use one event model.

A completed CBOR request is emitted as
`SessionEvent::Ctap2Request { channel, request }`. The caller executes
it through `AuthenticatorService` and passes the response to
`respond_ctap2`. The desktop runtime tracks each allocated channel separately
and queues service execution in arrival order, while keeping the report loop
available during user approval. Pending channels receive independent
keepalives and deadlines; the shared credential store and service remain
serialized.

A valid CTAPHID CANCEL removes a queued request before it can execute. For the
currently executing channel, it cancels pending user verification and discards
the eventual service response; the next queued request starts after that
service call returns. Channel expiry follows the same per-channel cleanup.
Cancelled or expired channels never receive a stale response. The service
executor should return CTAP2 `KEEPALIVE_CANCEL` when cancellation reaches an
active CTAP command. The transport owner must clear that channel's
`AuthenticatorService` continuation state when it receives a cancellation or
expiry event.

This layer does not own an OS device handle, background thread, or event loop.
Each platform backend remains responsible for attachment, report I/O, shutdown,
and delivering reports to this adapter. The desktop runtime clears service
continuations when expiry is reported, whether expiry is discovered during
report reception or while waiting for the next report.
