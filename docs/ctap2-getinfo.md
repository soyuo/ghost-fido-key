# CTAP2 GetInfo profile

`GetInfoProfile` requires explicit versions, AAGUID, options, maximum message
size, and PIN/UV protocol values before it can be encoded. There is no default
profile, so an unfinished authenticator cannot accidentally advertise support.

`GetInfoHandler::new` validates and stores that profile. Its payload handler
returns the encoded profile for an empty GetInfo payload and `InvalidLength`
when the payload is nonempty. `AuthenticatorService` owns command routing and
returns `InvalidCommand` for commands without an implementation. Configuration
errors are returned while constructing the handler and never become a
successful protocol response. Pass the resulting response to
`CtapHidSession::respond_ctap2_result` to frame its status and payload on the
request channel.
