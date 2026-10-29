# CTAPHID authenticator service adapter

`AuthenticatorHidSession` owns transport-neutral `CtapHidSession` state. The
transport owner passes each complete 64-byte output report to `receive_report`
with a monotonic timestamp. It returns expired channel IDs alongside the core
`SessionEvent`, so the caller can clear channel-scoped service state while
initialization, ping, error, and CTAP2 response reports use one event model.

A completed CBOR request is emitted as
`SessionEvent::Ctap2Request { channel, request }`. The caller executes
it through `AuthenticatorService` and passes the response to
`respond_ctap2`. This keeps the report loop available while the service waits
for user approval. The adapter allows one active CTAP2 request at a time and
returns CTAPHID `CHANNEL_BUSY` for another request until the first response is
framed.

A valid CTAPHID CANCEL cancels pending user verification only when it targets
the active CTAP2 channel. The service executor should return CTAP2
`KEEPALIVE_CANCEL` and frame it with `respond_ctap2`. Channel expiry also
cancels the active approval. The transport owner must clear that channel's
`AuthenticatorService` continuation state when it receives a cancellation or
expiry event.

This layer does not own an OS device handle, background thread, or event loop.
Each platform backend remains responsible for attachment, report I/O, shutdown,
and delivering reports to this adapter. The desktop runtime clears service
continuations when expiry is reported, whether expiry is discovered during
report reception or while waiting for the next report.
