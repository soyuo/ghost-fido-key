//! Platform-independent domain types for the Ghost FIDO authenticator.
//!
//! Protocol handling, credentials, cryptography, and persistence are not
//! implemented yet. Keep operating-system APIs out of this crate.

pub mod cbor;
pub mod ctap2;
pub mod ctaphid;

pub use cbor::{CborError, CborLimits, CborValue, decode as decode_cbor, decode_with_limits};
pub use ctap2::{Ctap2Command, Ctap2Error, Ctap2Request, Ctap2Status, encode_response};
pub use ctaphid::{
    BROADCAST_CHANNEL, ChannelError, CtapHidAssembler, CtapHidChannelAllocator, CtapHidCommand,
    CtapHidMessage, FrameError, encode_continuations, encode_initialization,
};

/// Protocol families the authenticator is intended to expose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// FIDO Client-to-Authenticator Protocol over HID.
    CtapHid,
}

/// Static information shown by the application before any device is attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub supported_protocols: &'static [Protocol],
}

impl ProductInfo {
    /// Returns metadata for this development scaffold.
    #[must_use]
    pub const fn current() -> Self {
        Self {
            name: "Ghost FIDO Key",
            version: env!("CARGO_PKG_VERSION"),
            supported_protocols: &[Protocol::CtapHid],
        }
    }
}
