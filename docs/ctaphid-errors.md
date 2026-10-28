# CTAPHID error reports

Dispatch failures are encoded as CTAPHID_ERROR initialization reports on the
request channel. The one-byte payload is the CTAPHID error code. Invalid report
framing remains a `FrameError` because malformed input may not contain a
trustworthy channel identifier for a response.
