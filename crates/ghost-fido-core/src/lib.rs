//! Platform-independent domain types for the Ghost FIDO authenticator.
//!
//! Protocol handling, credential selection and protected metadata persistence
//! are platform-independent. Keep operating-system APIs out of this crate.

pub mod cbor;
pub mod client_pin;
pub mod credentials;
pub mod ctap2;
pub mod ctaphid;

pub use cbor::{
    CborError, CborLimits, CborValue, decode as decode_cbor, decode_with_limits,
    encode as encode_cbor,
};
pub use client_pin::{
    PIN_ENCRYPTED_SIZE, PIN_HASH_SIZE, PIN_MAX_UTF8_BYTES, PIN_MIN_CODEPOINTS,
    PIN_UV_AUTH_PARAMETER_SIZE, PIN_UV_AUTH_PROTOCOL, PinCryptoError, PinKeyAgreement,
    PinManagementError, authenticate as client_pin_authenticate,
    configure_pin as configure_client_pin, decrypt as client_pin_decrypt,
    decrypt_pin as client_pin_decrypt_pin, encrypt as client_pin_encrypt,
    pin_hash as client_pin_hash, process_hmac_secret as client_pin_process_hmac_secret,
    validate_pin as client_pin_validate, verify_authentication as client_pin_verify_authentication,
};
pub use credentials::{
    CredentialError, CredentialId, CredentialKeyMetadata, CredentialKeyProtection,
    CredentialProtectionError, CredentialProtectionPolicy, CredentialProtector, CredentialRecord,
    CredentialStore, Es256PublicKey, HmacSecretMaterial, KeyHandle, ManagedCredential, PinState,
    RpIdHash,
};
pub use ctap2::{
    Ctap2Command, Ctap2Error, Ctap2Request, Ctap2Response, Ctap2Status, GetAssertionError,
    GetAssertionOptions, GetAssertionRequest, GetAssertionResponseError, GetInfoError,
    GetInfoHandler, GetInfoProfile, HmacSecretInput, MAX_CREDENTIAL_ID_SIZE, MakeCredentialError,
    MakeCredentialOptions, MakeCredentialRequest, MakeCredentialResponseError, MakeCredentialRp,
    MakeCredentialUser, PublicKeyCredentialParameter, encode_es256_cose_public_key,
    encode_get_assertion_response, encode_get_assertion_response_with_count,
    encode_get_assertion_response_with_count_and_presence_and_uv_and_extensions,
    encode_get_assertion_response_with_count_and_uv,
    encode_get_assertion_response_with_count_and_uv_and_extensions, encode_get_info,
    encode_make_credential_response, encode_make_credential_response_with_extensions,
    encode_response, get_assertion_authenticator_data,
    get_assertion_authenticator_data_with_presence_and_uv,
    get_assertion_authenticator_data_with_uv,
};
pub use ctaphid::{
    BROADCAST_CHANNEL, ChannelError, CtapHidAssembler, CtapHidChannelAllocator, CtapHidCommand,
    CtapHidDispatch, CtapHidErrorCode, CtapHidMessage, CtapHidSession, FrameError, HID_REPORT_SIZE,
    SessionEvent, dispatch as dispatch_ctaphid, encode_continuations, encode_ctap2_response,
    encode_error, encode_initialization,
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
