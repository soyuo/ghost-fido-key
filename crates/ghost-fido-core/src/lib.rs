//! Platform-independent domain types for the Ghost FIDO authenticator.
//!
//! Protocol handling, credential selection and protected metadata persistence
//! are platform-independent. Keep operating-system APIs out of this crate.

pub mod cbor;
pub mod credentials;
pub mod ctap2;
pub mod ctaphid;

pub use cbor::{
    CborError, CborLimits, CborValue, decode as decode_cbor, decode_with_limits,
    encode as encode_cbor,
};
pub use credentials::{
    CredentialError, CredentialId, CredentialKeyMetadata, CredentialKeyProtection,
    CredentialProtectionError, CredentialProtector, CredentialRecord, CredentialStore,
    Es256PublicKey, KeyHandle, RpIdHash,
};
pub use ctap2::{
    Ctap2Command, Ctap2Error, Ctap2Handler, Ctap2Request, Ctap2Response, Ctap2Status,
    GetAssertionError, GetAssertionOptions, GetAssertionRequest, GetAssertionResponseError,
    GetInfoError, GetInfoProfile, MAX_CREDENTIAL_ID_SIZE, MakeCredentialError,
    MakeCredentialOptions, MakeCredentialRequest, MakeCredentialResponseError, MakeCredentialRp,
    MakeCredentialUser, PublicKeyCredentialParameter, encode_es256_cose_public_key,
    encode_get_assertion_response, encode_get_info, encode_make_credential_response,
    encode_response, get_assertion_authenticator_data,
};
pub use ctaphid::{
    BROADCAST_CHANNEL, ChannelError, CtapHidAssembler, CtapHidChannelAllocator, CtapHidCommand,
    CtapHidDispatch, CtapHidErrorCode, CtapHidMessage, CtapHidSession, FrameError, SessionEvent,
    dispatch as dispatch_ctaphid, encode_continuations, encode_ctap2_response, encode_error,
    encode_initialization,
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
