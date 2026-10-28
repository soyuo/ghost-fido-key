# CTAPHID authenticator service adapter

`AuthenticatorHidSession` joins the transport-neutral `CtapHidSession` to a
configured `AuthenticatorService`. The transport owner passes each complete
64-byte output report to `receive_report` with a monotonic timestamp and sends
any reports returned in `AuthenticatorHidEvent::Reports` back to the HID host.
Initialization and ping responses are already framed by the core session;
typed CTAP2 requests are routed with their originating channel and framed by
the adapter.

The adapter returns `Pending` while a fragmented request is incomplete,
`Cancelled(channel)` for CTAPHID CANCEL, and protocol `Message` events the
transport owner must handle. Framing and provider failures remain structured
errors. Call `expire` during the transport loop to release expired channels and
their GetNextAssertion continuation state even when no new report arrives.

This layer does not own an OS device handle, background thread, or event loop.
Each platform backend remains responsible for attachment, report I/O, shutdown,
and delivering reports to this adapter. The Tauri desktop app is not wired to a
live backend yet.
