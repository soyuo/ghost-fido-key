# CTAPHID authenticator service adapter

`AuthenticatorHidSession` owns transport-neutral `CtapHidSession` state. The
transport owner passes each complete 64-byte output report to `receive_report`
with a monotonic timestamp. It returns expired channel IDs alongside the core
`SessionEvent`, so the caller can clear channel-scoped service state while
initialization, ping, error, and CTAP2 response reports use one event model.

A completed CBOR request is emitted as
`SessionEvent::Ctap2Request { channel, request }`. The caller executes
it through `AuthenticatorService` and passes the response to
`respond_ctap2`. A transaction claims the HID session when its initialization
packet arrives and holds it through the response or abort. If a different
channel starts a request while that transaction is active, the session returns
`CTAPHID_ERROR(ERR_CHANNEL_BUSY)` on the requesting channel without dispatching
or queuing the request. The active transaction continues normally. The desktop
runtime keeps the report loop available during user approval while serializing
authenticator service execution.

A valid CTAPHID CANCEL completes the original CBOR transaction with
`KEEPALIVE_CANCEL`; the CANCEL command itself receives no response. A queued
request can be completed immediately when it reaches dispatch order. For the
currently executing request, the runtime cancels pending user verification,
discards the eventual service result, and sends `KEEPALIVE_CANCEL` after that
call returns.

A valid same-channel INIT resynchronization sends its INIT response, aborts the
prior CBOR transaction, and discards that request's eventual service result.
Request IDs keep the old completion separate from a new request on the same
channel, which can execute after the prior service call unwinds. Channel expiry
uses the same stale-result protection but emits no CBOR response. The transport
owner must clear that channel's `AuthenticatorService` continuation state on
cancellation, resynchronization, or expiry.

This layer does not own an OS device handle, background thread, or event loop.
Each platform backend remains responsible for attachment, report I/O, shutdown,
and delivering reports to this adapter. The desktop runtime clears service
continuations when expiry is reported, whether expiry is discovered during
report reception or while waiting for the next report.
