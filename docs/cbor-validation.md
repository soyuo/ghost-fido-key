# Bounded CBOR validation

The core decoder accepts only definite-length unsigned/negative integers,
byte strings, UTF-8 text, arrays, maps, booleans, and null. The default limits
are 16 nesting levels, 128 collection items, and 8192 bytes. Truncation,
indefinite-length values, unsupported simple/float values, invalid UTF-8, and
trailing data are rejected before CTAP2 handlers receive input.
