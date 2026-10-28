# CTAP2 GetInfo profile

`GetInfoProfile` requires explicit versions, AAGUID, options, maximum message
size, and PIN/UV protocol values before it can be encoded. There is no default
profile, so an unfinished authenticator cannot accidentally advertise support.

`Ctap2Handler::new` validates and stores that profile. Its request handler
returns the encoded profile for a parameter-free GetInfo command, `InvalidLength`
when GetInfo has parameters, and `InvalidCommand` for known commands without a
handler. Configuration errors are returned while constructing the handler and
never become a successful protocol response. Pass the resulting response to
`CtapHidSession::respond_ctap2_result` to frame its status and payload on the
request channel.
