//! Minimal CTAP2 command and status boundary.

use crate::{
    cbor::{CborError, CborValue, decode, encode},
    credentials::{
        CredentialBlob, CredentialProtectionPolicy, CredentialRecord, CredentialStore,
        Es256PublicKey, LargeBlobKey, MAX_CREDENTIAL_BLOB_LENGTH, RpIdHash,
    },
};
use zeroize::Zeroizing;

use core::fmt;
use sha2::{Digest, Sha256};

pub const MAX_CREDENTIAL_ID_SIZE: usize = 1023;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Ctap2Command {
    MakeCredential = 0x01,
    GetAssertion = 0x02,
    GetInfo = 0x04,
    ClientPin = 0x06,
    Reset = 0x07,
    GetNextAssertion = 0x08,
    CredentialManagement = 0x0a,
    Selection = 0x0b,
    LargeBlobs = 0x0c,
    Config = 0x0d,
}

impl TryFrom<u8> for Ctap2Command {
    type Error = Ctap2Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::MakeCredential),
            0x02 => Ok(Self::GetAssertion),
            0x04 => Ok(Self::GetInfo),
            0x06 => Ok(Self::ClientPin),
            0x07 => Ok(Self::Reset),
            0x08 => Ok(Self::GetNextAssertion),
            0x0a => Ok(Self::CredentialManagement),
            0x0b => Ok(Self::Selection),
            0x0c => Ok(Self::LargeBlobs),
            0x0d => Ok(Self::Config),
            _ => Err(Ctap2Error::UnsupportedCommand(value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Ctap2Status {
    Success = 0x00,
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    InvalidSequence = 0x04,
    ChannelBusy = 0x06,
    Other = 0x7f,
    CborUnexpectedType = 0x11,
    InvalidCbor = 0x12,
    MissingParameter = 0x14,
    CredentialExcluded = 0x19,
    LargeBlobStorageFull = 0x18,
    UnsupportedAlgorithm = 0x26,
    OperationDenied = 0x27,
    UnsupportedOption = 0x2b,
    InvalidOption = 0x2c,
    KeepaliveCancel = 0x2d,
    NoCredentials = 0x2e,
    UserActionTimeout = 0x2f,
    UserActionPending = 0x23,
    RequestTooLarge = 0x39,
    NotAllowed = 0x30,
    PinInvalid = 0x31,
    PinBlocked = 0x32,
    PinAuthInvalid = 0x33,
    PinAuthBlocked = 0x34,
    PinNotSet = 0x35,
    PinUvAuthTokenRequired = 0x36,
    PinPolicyViolation = 0x37,
    InvalidSubcommand = 0x3e,
    IntegrityFailure = 0x3d,
    UnauthorizedPermission = 0x40,
}

impl Ctap2Status {
    #[must_use]
    pub const fn wire(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ctap2Error {
    EmptyRequest,
    UnsupportedCommand(u8),
    InvalidCbor(CborError),
}

impl fmt::Display for Ctap2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyRequest => f.write_str("CTAP2 request is empty"),
            Self::UnsupportedCommand(c) => write!(f, "unsupported CTAP2 command 0x{c:02x}"),
            Self::InvalidCbor(error) => write!(f, "invalid CTAP2 CBOR payload: {error}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ctap2Request {
    command: Ctap2Command,
    payload: Vec<u8>,
    decoded_payload: Option<CborValue>,
}

impl Ctap2Request {
    pub fn decode(bytes: &[u8]) -> Result<Self, Ctap2Error> {
        let (&command, payload) = bytes.split_first().ok_or(Ctap2Error::EmptyRequest)?;
        let command = command.try_into()?;
        Self::new(command, payload.to_vec())
    }

    pub fn new(command: Ctap2Command, payload: Vec<u8>) -> Result<Self, Ctap2Error> {
        let decoded_payload = if payload.is_empty() || command == Ctap2Command::Selection {
            None
        } else {
            Some(decode(&payload).map_err(Ctap2Error::InvalidCbor)?)
        };
        Ok(Self {
            command,
            payload,
            decoded_payload,
        })
    }

    #[must_use]
    pub const fn command(&self) -> Ctap2Command {
        self.command
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Splits a validated request so typed command parsing can consume its CBOR tree.
    #[must_use]
    pub fn into_parts(self) -> (Ctap2Command, Vec<u8>, Option<CborValue>) {
        (self.command, self.payload, self.decoded_payload)
    }
}

#[must_use]
pub fn encode_response(status: Ctap2Status, payload: &[u8]) -> Vec<u8> {
    let mut response = Vec::with_capacity(payload.len() + 1);
    response.push(status.wire());
    response.extend_from_slice(payload);
    response
}

#[must_use]
pub fn encode_es256_cose_public_key(public_key: &Es256PublicKey) -> Result<Vec<u8>, CborError> {
    encode(&CborValue::Map(vec![
        (CborValue::Unsigned(1), CborValue::Unsigned(2)),
        (CborValue::Unsigned(3), CborValue::Negative(-7)),
        (CborValue::Negative(-1), CborValue::Unsigned(1)),
        (
            CborValue::Negative(-2),
            CborValue::Bytes(public_key.x.to_vec()),
        ),
        (
            CborValue::Negative(-3),
            CborValue::Bytes(public_key.y.to_vec()),
        ),
    ]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MakeCredentialResponseError {
    EmptyCredentialId,
    CredentialIdTooLong(usize),
    CborEncoding(CborError),
}

impl From<CborError> for MakeCredentialResponseError {
    fn from(error: CborError) -> Self {
        Self::CborEncoding(error)
    }
}

/// Encodes a CTAP2 `fmt: none` MakeCredential response.
pub fn encode_make_credential_response(
    rp_id_hash: RpIdHash,
    aaguid: [u8; 16],
    credential_id: &[u8],
    public_key: &Es256PublicKey,
    user_verified: bool,
) -> Result<Ctap2Response, MakeCredentialResponseError> {
    encode_make_credential_response_with_extensions(
        rp_id_hash,
        aaguid,
        credential_id,
        public_key,
        user_verified,
        None,
    )
}

pub fn encode_make_credential_response_with_extensions(
    rp_id_hash: RpIdHash,
    aaguid: [u8; 16],
    credential_id: &[u8],
    public_key: &Es256PublicKey,
    user_verified: bool,
    extensions: Option<CborValue>,
) -> Result<Ctap2Response, MakeCredentialResponseError> {
    encode_make_credential_response_with_extensions_and_large_blob_key(
        rp_id_hash,
        aaguid,
        credential_id,
        public_key,
        user_verified,
        extensions,
        None,
    )
}

pub fn encode_make_credential_response_with_extensions_and_large_blob_key(
    rp_id_hash: RpIdHash,
    aaguid: [u8; 16],
    credential_id: &[u8],
    public_key: &Es256PublicKey,
    user_verified: bool,
    extensions: Option<CborValue>,
    large_blob_key: Option<&LargeBlobKey>,
) -> Result<Ctap2Response, MakeCredentialResponseError> {
    if credential_id.is_empty() {
        return Err(MakeCredentialResponseError::EmptyCredentialId);
    }
    if credential_id.len() > MAX_CREDENTIAL_ID_SIZE {
        return Err(MakeCredentialResponseError::CredentialIdTooLong(
            credential_id.len(),
        ));
    }

    let mut authenticator_data = Vec::with_capacity(37 + 18 + credential_id.len() + 77);
    authenticator_data.extend_from_slice(&rp_id_hash);
    let flags = 0x01
        | 0x40
        | if user_verified { 0x04 } else { 0 }
        | if extensions.is_some() { 0x80 } else { 0 };
    authenticator_data.push(flags);
    authenticator_data.extend_from_slice(&0_u32.to_be_bytes());
    authenticator_data.extend_from_slice(&aaguid);
    authenticator_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    authenticator_data.extend_from_slice(credential_id);
    authenticator_data.extend_from_slice(&encode_es256_cose_public_key(public_key)?);
    if let Some(extensions) = extensions {
        authenticator_data.extend_from_slice(&encode(&extensions)?);
    }

    let mut response = vec![
        (CborValue::Unsigned(1), CborValue::Text("none".into())),
        (CborValue::Unsigned(2), CborValue::Bytes(authenticator_data)),
        (CborValue::Unsigned(3), CborValue::Map(Vec::new())),
    ];
    if let Some(key) = large_blob_key {
        response.push((
            CborValue::Unsigned(5),
            CborValue::Bytes(key.as_bytes().to_vec()),
        ));
    }
    let response = Zeroizing::new(CborValue::Map(response));
    Ok(Ctap2Response {
        status: Ctap2Status::Success,
        payload: encode(&response)?,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetAssertionResponseError {
    EmptyCredentialId,
    CredentialIdTooLong(usize),
    EmptySignature,
    SignatureTooLong(usize),
    InvalidUserHandle,
    InvalidNumberOfCredentials,
    CborEncoding(CborError),
}

impl From<CborError> for GetAssertionResponseError {
    fn from(error: CborError) -> Self {
        Self::CborEncoding(error)
    }
}

#[must_use]
pub fn get_assertion_authenticator_data(rp_id_hash: RpIdHash, sign_count: u32) -> [u8; 37] {
    get_assertion_authenticator_data_with_uv(rp_id_hash, sign_count, false)
}

#[must_use]
pub fn get_assertion_authenticator_data_with_uv(
    rp_id_hash: RpIdHash,
    sign_count: u32,
    user_verified: bool,
) -> [u8; 37] {
    get_assertion_authenticator_data_with_presence_and_uv(
        rp_id_hash,
        sign_count,
        true,
        user_verified,
    )
}

#[must_use]
pub fn get_assertion_authenticator_data_with_presence_and_uv(
    rp_id_hash: RpIdHash,
    sign_count: u32,
    user_present: bool,
    user_verified: bool,
) -> [u8; 37] {
    let mut data = [0; 37];
    data[..32].copy_from_slice(&rp_id_hash);
    data[32] = (if user_present { 0x01 } else { 0 }) | if user_verified { 0x04 } else { 0 }; // UP and validated PIN UV.
    data[33..].copy_from_slice(&sign_count.to_be_bytes());
    data
}

/// Encodes one successful CTAP2 `authenticatorGetAssertion` response.
///
/// The caller supplies an already-created signature. This convenience encoder
/// sets UP and leaves UV clear; signing and user approval remain outside it.
pub fn encode_get_assertion_response(
    rp_id_hash: RpIdHash,
    credential_id: &[u8],
    user_handle: Option<&[u8]>,
    signature: &[u8],
    sign_count: u32,
) -> Result<Ctap2Response, GetAssertionResponseError> {
    encode_get_assertion_response_with_count(
        rp_id_hash,
        credential_id,
        user_handle,
        signature,
        sign_count,
        None,
    )
}

pub fn encode_get_assertion_response_with_count(
    rp_id_hash: RpIdHash,
    credential_id: &[u8],
    user_handle: Option<&[u8]>,
    signature: &[u8],
    sign_count: u32,
    number_of_credentials: Option<u64>,
) -> Result<Ctap2Response, GetAssertionResponseError> {
    encode_get_assertion_response_with_count_and_uv(
        rp_id_hash,
        credential_id,
        user_handle,
        signature,
        sign_count,
        number_of_credentials,
        false,
    )
}

pub fn encode_get_assertion_response_with_count_and_uv(
    rp_id_hash: RpIdHash,
    credential_id: &[u8],
    user_handle: Option<&[u8]>,
    signature: &[u8],
    sign_count: u32,
    number_of_credentials: Option<u64>,
    user_verified: bool,
) -> Result<Ctap2Response, GetAssertionResponseError> {
    encode_get_assertion_response_with_count_and_uv_and_extensions(
        rp_id_hash,
        credential_id,
        user_handle,
        signature,
        sign_count,
        number_of_credentials,
        user_verified,
        None,
    )
}

pub fn encode_get_assertion_response_with_count_and_uv_and_extensions(
    rp_id_hash: RpIdHash,
    credential_id: &[u8],
    user_handle: Option<&[u8]>,
    signature: &[u8],
    sign_count: u32,
    number_of_credentials: Option<u64>,
    user_verified: bool,
    extensions: Option<CborValue>,
) -> Result<Ctap2Response, GetAssertionResponseError> {
    encode_get_assertion_response_with_count_and_presence_and_uv_and_extensions(
        rp_id_hash,
        credential_id,
        user_handle,
        signature,
        sign_count,
        number_of_credentials,
        true,
        user_verified,
        extensions,
    )
}

pub fn encode_get_assertion_response_with_count_and_presence_and_uv_and_extensions(
    rp_id_hash: RpIdHash,
    credential_id: &[u8],
    user_handle: Option<&[u8]>,
    signature: &[u8],
    sign_count: u32,
    number_of_credentials: Option<u64>,
    user_present: bool,
    user_verified: bool,
    extensions: Option<CborValue>,
) -> Result<Ctap2Response, GetAssertionResponseError> {
    encode_get_assertion_response_with_count_and_presence_and_uv_and_extensions_and_large_blob_key(
        rp_id_hash,
        credential_id,
        user_handle,
        signature,
        sign_count,
        number_of_credentials,
        user_present,
        user_verified,
        extensions,
        None,
    )
}

pub fn encode_get_assertion_response_with_count_and_presence_and_uv_and_extensions_and_large_blob_key(
    rp_id_hash: RpIdHash,
    credential_id: &[u8],
    user_handle: Option<&[u8]>,
    signature: &[u8],
    sign_count: u32,
    number_of_credentials: Option<u64>,
    user_present: bool,
    user_verified: bool,
    extensions: Option<CborValue>,
    large_blob_key: Option<&LargeBlobKey>,
) -> Result<Ctap2Response, GetAssertionResponseError> {
    if credential_id.is_empty() {
        return Err(GetAssertionResponseError::EmptyCredentialId);
    }
    if credential_id.len() > MAX_CREDENTIAL_ID_SIZE {
        return Err(GetAssertionResponseError::CredentialIdTooLong(
            credential_id.len(),
        ));
    }
    if signature.is_empty() {
        return Err(GetAssertionResponseError::EmptySignature);
    }
    if signature.len() > 128 {
        return Err(GetAssertionResponseError::SignatureTooLong(signature.len()));
    }
    if user_handle.is_some_and(|handle| handle.len() > 64) {
        return Err(GetAssertionResponseError::InvalidUserHandle);
    }
    if number_of_credentials.is_some_and(|count| count < 2) {
        return Err(GetAssertionResponseError::InvalidNumberOfCredentials);
    }

    let mut authenticator_data = Zeroizing::new(
        get_assertion_authenticator_data_with_presence_and_uv(
            rp_id_hash,
            sign_count,
            user_present,
            user_verified,
        )
        .to_vec(),
    );
    if let Some(extensions) = extensions {
        authenticator_data[32] |= 0x80;
        let encoded_extensions = Zeroizing::new(encode(&Zeroizing::new(extensions))?);
        authenticator_data.extend_from_slice(&encoded_extensions);
    }

    let credential = CborValue::Map(vec![
        (
            CborValue::Text("type".into()),
            CborValue::Text("public-key".into()),
        ),
        (
            CborValue::Text("id".into()),
            CborValue::Bytes(credential_id.to_vec()),
        ),
    ]);
    let mut response = vec![
        (CborValue::Unsigned(1), credential),
        (
            CborValue::Unsigned(2),
            CborValue::Bytes(authenticator_data.to_vec()),
        ),
        (CborValue::Unsigned(3), CborValue::Bytes(signature.to_vec())),
    ];
    if let Some(count) = number_of_credentials {
        response.push((CborValue::Unsigned(5), CborValue::Unsigned(count)));
    }
    if let Some(user_handle) = user_handle {
        response.push((
            CborValue::Unsigned(4),
            CborValue::Map(vec![(
                CborValue::Text("id".into()),
                CborValue::Bytes(user_handle.to_vec()),
            )]),
        ));
    }
    if let Some(key) = large_blob_key {
        response.push((
            CborValue::Unsigned(7),
            CborValue::Bytes(key.as_bytes().to_vec()),
        ));
    }

    let response = Zeroizing::new(CborValue::Map(response));
    let payload = Zeroizing::new(encode(&response)?);
    Ok(Ctap2Response {
        status: Ctap2Status::Success,
        payload: payload.to_vec(),
    })
}

#[derive(Clone, PartialEq, Eq)]
pub struct Ctap2Response {
    pub status: Ctap2Status,
    pub payload: Vec<u8>,
}

impl fmt::Debug for Ctap2Response {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ctap2Response")
            .field("status", &self.status)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl Ctap2Response {
    /// Creates a CTAP2 response with the given status and no response payload.
    #[must_use]
    pub fn error(status: Ctap2Status) -> Self {
        Self {
            status,
            payload: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAssertionRequest {
    pub rp_id: String,
    pub client_data_hash: [u8; 32],
    pub allow_list: Option<Vec<Vec<u8>>>,
    pub options: GetAssertionOptions,
    pub hmac_secret: Option<HmacSecretInput>,
    pub large_blob_key: bool,
    pub get_cred_blob: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HmacSecretInput {
    pub key_agreement: CborValue,
    pub salt_enc: Vec<u8>,
    pub salt_auth: Vec<u8>,
    pub pin_uv_auth_protocol: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GetAssertionOptions {
    pub user_presence: Option<bool>,
    pub user_verification: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakeCredentialRp {
    pub id: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakeCredentialUser {
    pub id: Vec<u8>,
    pub name: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKeyCredentialParameter {
    pub algorithm: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MakeCredentialOptions {
    pub resident_key: Option<bool>,
    pub user_verification: Option<bool>,
    pub user_presence: Option<bool>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MakeCredentialRequest {
    pub client_data_hash: [u8; 32],
    pub rp: MakeCredentialRp,
    pub user: MakeCredentialUser,
    pub public_key_credential_parameters: Vec<PublicKeyCredentialParameter>,
    pub exclude_list: Option<Vec<Vec<u8>>>,
    pub options: MakeCredentialOptions,
    pub hmac_secret: bool,
    pub cred_protect: Option<CredentialProtectionPolicy>,
    pub enforce_credential_protection_policy: bool,
    pub large_blob_key: bool,
    pub cred_blob: Option<CredentialBlob>,
}

impl fmt::Debug for MakeCredentialRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MakeCredentialRequest")
            .field("client_data_hash", &"[REDACTED]")
            .field("rp", &self.rp)
            .field("user", &self.user)
            .field(
                "public_key_credential_parameters",
                &self.public_key_credential_parameters,
            )
            .field("exclude_list", &self.exclude_list)
            .field("options", &self.options)
            .field("hmac_secret", &self.hmac_secret)
            .field("cred_protect", &self.cred_protect)
            .field(
                "enforce_credential_protection_policy",
                &self.enforce_credential_protection_policy,
            )
            .field("large_blob_key", &self.large_blob_key)
            .field("cred_blob", &self.cred_blob.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MakeCredentialError {
    InvalidCbor(CborError),
    MissingParameter(u64),
    UnexpectedType(u64),
    InvalidParameter(u64),
    InvalidOption,
}

impl From<GetAssertionError> for MakeCredentialError {
    fn from(error: GetAssertionError) -> Self {
        match error {
            GetAssertionError::InvalidCbor(error) => Self::InvalidCbor(error),
            GetAssertionError::MissingParameter(parameter) => Self::MissingParameter(parameter),
            GetAssertionError::UnexpectedType(parameter) => Self::UnexpectedType(parameter),
            GetAssertionError::InvalidParameter(parameter) => Self::InvalidParameter(parameter),
            GetAssertionError::InvalidOption => Self::InvalidOption,
        }
    }
}

impl MakeCredentialError {
    #[must_use]
    pub const fn status(&self) -> Ctap2Status {
        match self {
            Self::InvalidCbor(_) => Ctap2Status::InvalidCbor,
            Self::MissingParameter(_) => Ctap2Status::MissingParameter,
            Self::UnexpectedType(_) => Ctap2Status::CborUnexpectedType,
            Self::InvalidParameter(_) => Ctap2Status::InvalidParameter,
            Self::InvalidOption => Ctap2Status::InvalidOption,
        }
    }
}

impl MakeCredentialRequest {
    pub fn decode(payload: &[u8]) -> Result<Self, MakeCredentialError> {
        let value = decode(payload).map_err(MakeCredentialError::InvalidCbor)?;
        Self::decode_value(value)
    }

    pub fn decode_value(value: CborValue) -> Result<Self, MakeCredentialError> {
        let CborValue::Map(entries) = value else {
            return Err(MakeCredentialError::UnexpectedType(0));
        };
        let mut client_data_hash = None;
        let mut rp = None;
        let mut user = None;
        let mut public_key_credential_parameters = None;
        let mut exclude_list = None;
        let mut options = None;
        let mut extensions = None;
        for (key, value) in entries {
            let CborValue::Unsigned(key) = key else {
                continue;
            };
            match key {
                1 => {
                    if client_data_hash.is_some() {
                        return Err(MakeCredentialError::InvalidParameter(1));
                    }
                    let CborValue::Bytes(hash) = value else {
                        return Err(MakeCredentialError::UnexpectedType(1));
                    };
                    client_data_hash = Some(
                        hash.try_into()
                            .map_err(|_| MakeCredentialError::InvalidParameter(1))?,
                    );
                }
                2 => {
                    if rp.is_some() {
                        return Err(MakeCredentialError::InvalidParameter(2));
                    }
                    rp = Some(parse_make_credential_rp(value)?);
                }
                3 => {
                    if user.is_some() {
                        return Err(MakeCredentialError::InvalidParameter(3));
                    }
                    user = Some(parse_make_credential_user(value)?);
                }
                4 => {
                    if public_key_credential_parameters.is_some() {
                        return Err(MakeCredentialError::InvalidParameter(4));
                    }
                    public_key_credential_parameters = Some(parse_public_key_parameters(value)?);
                }
                5 => {
                    if exclude_list.is_some() {
                        return Err(MakeCredentialError::InvalidParameter(5));
                    }
                    let CborValue::Array(descriptors) = value else {
                        return Err(MakeCredentialError::UnexpectedType(5));
                    };
                    exclude_list = Some(parse_credential_descriptors(descriptors, 5)?);
                }
                6 => {
                    if extensions.is_some() {
                        return Err(MakeCredentialError::InvalidParameter(6));
                    }
                    extensions = Some(parse_make_credential_extensions(value)?);
                }
                7 => {
                    if options.is_some() {
                        return Err(MakeCredentialError::InvalidParameter(7));
                    }
                    options = Some(parse_make_credential_options(value)?);
                }
                _ => {}
            }
        }
        let public_key_credential_parameters =
            public_key_credential_parameters.ok_or(MakeCredentialError::MissingParameter(4))?;
        if public_key_credential_parameters.is_empty() {
            return Err(MakeCredentialError::InvalidParameter(4));
        }
        let options = options.unwrap_or_default();
        let extensions = extensions.unwrap_or((false, None, false, false, None));
        if extensions.3 && options.resident_key != Some(true) {
            return Err(MakeCredentialError::InvalidOption);
        }
        Ok(Self {
            client_data_hash: client_data_hash.ok_or(MakeCredentialError::MissingParameter(1))?,
            rp: rp.ok_or(MakeCredentialError::MissingParameter(2))?,
            user: user.ok_or(MakeCredentialError::MissingParameter(3))?,
            public_key_credential_parameters,
            exclude_list,
            options,
            hmac_secret: extensions.0,
            cred_protect: extensions.1,
            enforce_credential_protection_policy: extensions.2,
            large_blob_key: extensions.3,
            cred_blob: extensions.4,
        })
    }

    #[must_use]
    pub fn has_excluded_credential(&self, store: &CredentialStore) -> bool {
        self.exclude_list.as_ref().is_some_and(|exclude_list| {
            store.has_matching_credentials(self.rp_id_hash(), exclude_list)
        })
    }

    #[must_use]
    pub fn has_excluded_credential_requiring_uv(&self, store: &CredentialStore) -> bool {
        self.exclude_list.as_ref().is_some_and(|exclude_list| {
            store
                .find_for_assertion(self.rp_id_hash(), Some(exclude_list))
                .iter()
                .any(|record| {
                    record.cred_protect == CredentialProtectionPolicy::UserVerificationRequired
                })
        })
    }

    #[must_use]
    pub fn rp_id_hash(&self) -> RpIdHash {
        Sha256::digest(self.rp.id.as_bytes()).into()
    }
}

fn parse_make_credential_rp(value: CborValue) -> Result<MakeCredentialRp, MakeCredentialError> {
    let CborValue::Map(fields) = value else {
        return Err(MakeCredentialError::UnexpectedType(2));
    };
    let mut id = None;
    let mut name = None;
    for (key, value) in fields {
        let CborValue::Text(key) = key else {
            continue;
        };
        match key.as_str() {
            "id" => {
                if id.is_some() {
                    return Err(MakeCredentialError::InvalidParameter(2));
                }
                let CborValue::Text(value) = value else {
                    return Err(MakeCredentialError::UnexpectedType(2));
                };
                if value.is_empty() {
                    return Err(MakeCredentialError::InvalidParameter(2));
                }
                id = Some(value);
            }
            "name" => {
                if name.is_some() {
                    return Err(MakeCredentialError::InvalidParameter(2));
                }
                let CborValue::Text(value) = value else {
                    return Err(MakeCredentialError::UnexpectedType(2));
                };
                name = Some(value);
            }
            _ => {}
        }
    }
    Ok(MakeCredentialRp {
        id: id.ok_or(MakeCredentialError::UnexpectedType(2))?,
        name,
    })
}

fn parse_make_credential_user(value: CborValue) -> Result<MakeCredentialUser, MakeCredentialError> {
    let CborValue::Map(fields) = value else {
        return Err(MakeCredentialError::UnexpectedType(3));
    };
    let mut id = None;
    let mut name = None;
    let mut display_name = None;
    for (key, value) in fields {
        let CborValue::Text(key) = key else {
            continue;
        };
        match key.as_str() {
            "id" => {
                if id.is_some() {
                    return Err(MakeCredentialError::InvalidParameter(3));
                }
                let CborValue::Bytes(value) = value else {
                    return Err(MakeCredentialError::UnexpectedType(3));
                };
                if value.len() > 64 {
                    return Err(MakeCredentialError::InvalidParameter(3));
                }
                id = Some(value);
            }
            "name" => {
                if name.is_some() {
                    return Err(MakeCredentialError::InvalidParameter(3));
                }
                let CborValue::Text(value) = value else {
                    return Err(MakeCredentialError::UnexpectedType(3));
                };
                name = Some(value);
            }
            "displayName" => {
                if display_name.is_some() {
                    return Err(MakeCredentialError::InvalidParameter(3));
                }
                let CborValue::Text(value) = value else {
                    return Err(MakeCredentialError::UnexpectedType(3));
                };
                display_name = Some(value);
            }
            _ => {}
        }
    }
    Ok(MakeCredentialUser {
        id: id.ok_or(MakeCredentialError::UnexpectedType(3))?,
        name,
        display_name,
    })
}

fn parse_public_key_parameters(
    value: CborValue,
) -> Result<Vec<PublicKeyCredentialParameter>, MakeCredentialError> {
    let CborValue::Array(parameters) = value else {
        return Err(MakeCredentialError::UnexpectedType(4));
    };
    let mut parsed: Vec<PublicKeyCredentialParameter> = Vec::with_capacity(parameters.len());
    for parameter in parameters {
        let CborValue::Map(fields) = parameter else {
            return Err(MakeCredentialError::UnexpectedType(4));
        };
        let mut credential_type = None;
        let mut algorithm = None;
        for (key, value) in fields {
            let CborValue::Text(key) = key else {
                continue;
            };
            match key.as_str() {
                "type" => {
                    if credential_type.is_some() {
                        return Err(MakeCredentialError::InvalidParameter(4));
                    }
                    let CborValue::Text(value) = value else {
                        return Err(MakeCredentialError::UnexpectedType(4));
                    };
                    if value != "public-key" {
                        return Err(MakeCredentialError::InvalidParameter(4));
                    }
                    credential_type = Some(());
                }
                "alg" => {
                    if algorithm.is_some() {
                        return Err(MakeCredentialError::InvalidParameter(4));
                    }
                    algorithm = Some(match value {
                        CborValue::Negative(value) => value,
                        CborValue::Unsigned(value) => value
                            .try_into()
                            .map_err(|_| MakeCredentialError::InvalidParameter(4))?,
                        _ => return Err(MakeCredentialError::UnexpectedType(4)),
                    });
                }
                _ => {}
            }
        }
        if credential_type.is_none() {
            return Err(MakeCredentialError::UnexpectedType(4));
        }
        let algorithm = algorithm.ok_or(MakeCredentialError::UnexpectedType(4))?;
        if parsed.iter().any(|entry| entry.algorithm == algorithm) {
            return Err(MakeCredentialError::InvalidParameter(4));
        }
        parsed.push(PublicKeyCredentialParameter { algorithm });
    }
    Ok(parsed)
}

fn parse_make_credential_options(
    value: CborValue,
) -> Result<MakeCredentialOptions, MakeCredentialError> {
    let CborValue::Map(entries) = value else {
        return Err(MakeCredentialError::UnexpectedType(7));
    };
    let mut options = MakeCredentialOptions::default();
    for (key, value) in entries {
        let CborValue::Text(key) = key else {
            continue;
        };
        let slot = match key.as_str() {
            "rk" => &mut options.resident_key,
            "uv" => &mut options.user_verification,
            "up" => &mut options.user_presence,
            _ => continue,
        };
        if slot.is_some() {
            return Err(MakeCredentialError::InvalidParameter(7));
        }
        let CborValue::Bool(value) = value else {
            return Err(MakeCredentialError::UnexpectedType(7));
        };
        *slot = Some(value);
    }
    Ok(options)
}

fn parse_make_credential_extensions(
    value: CborValue,
) -> Result<
    (
        bool,
        Option<CredentialProtectionPolicy>,
        bool,
        bool,
        Option<CredentialBlob>,
    ),
    MakeCredentialError,
> {
    let CborValue::Map(entries) = value else {
        return Err(MakeCredentialError::UnexpectedType(6));
    };
    let mut requested = None;
    let mut cred_protect = None;
    let mut enforce_policy = None;
    let mut large_blob_key = None;
    let mut cred_blob = None;
    for (key, value) in entries {
        let CborValue::Text(key) = key else {
            continue;
        };
        match key.as_str() {
            "hmac-secret" => {
                if requested.is_some() {
                    return Err(MakeCredentialError::InvalidParameter(6));
                }
                let CborValue::Bool(value) = value else {
                    return Err(MakeCredentialError::UnexpectedType(6));
                };
                requested = Some(value);
            }
            "credProtect" => {
                if cred_protect.is_some() {
                    return Err(MakeCredentialError::InvalidParameter(6));
                }
                let CborValue::Unsigned(level) = value else {
                    return Err(MakeCredentialError::UnexpectedType(6));
                };
                cred_protect = Some(match level {
                    1 => CredentialProtectionPolicy::UserVerificationOptional,
                    2 => CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList,
                    3 => CredentialProtectionPolicy::UserVerificationRequired,
                    _ => return Err(MakeCredentialError::InvalidParameter(6)),
                });
            }
            "enforceCredentialProtectionPolicy" => {
                if enforce_policy.is_some() {
                    return Err(MakeCredentialError::InvalidParameter(6));
                }
                let CborValue::Bool(value) = value else {
                    return Err(MakeCredentialError::UnexpectedType(6));
                };
                enforce_policy = Some(value);
            }
            "largeBlobKey" => {
                if large_blob_key.is_some() {
                    return Err(MakeCredentialError::InvalidParameter(6));
                }
                if value != CborValue::Bool(true) {
                    return Err(MakeCredentialError::InvalidOption);
                }
                large_blob_key = Some(true);
            }
            "credBlob" => {
                if cred_blob.is_some() {
                    return Err(MakeCredentialError::InvalidParameter(6));
                }
                let CborValue::Bytes(bytes) = value else {
                    return Err(MakeCredentialError::UnexpectedType(6));
                };
                cred_blob = Some(CredentialBlob::new(bytes));
            }
            _ => {}
        }
    }
    Ok((
        requested.unwrap_or(false),
        cred_protect,
        enforce_policy.unwrap_or(false),
        large_blob_key.unwrap_or(false),
        cred_blob,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetAssertionError {
    InvalidCbor(CborError),
    MissingParameter(u64),
    UnexpectedType(u64),
    InvalidParameter(u64),
    InvalidOption,
}

impl GetAssertionError {
    #[must_use]
    pub const fn status(&self) -> Ctap2Status {
        match self {
            Self::InvalidCbor(_) => Ctap2Status::InvalidCbor,
            Self::MissingParameter(_) => Ctap2Status::MissingParameter,
            Self::UnexpectedType(_) => Ctap2Status::CborUnexpectedType,
            Self::InvalidParameter(_) => Ctap2Status::InvalidParameter,
            Self::InvalidOption => Ctap2Status::InvalidOption,
        }
    }
}

impl GetAssertionRequest {
    pub fn decode(payload: &[u8]) -> Result<Self, GetAssertionError> {
        let value = decode(payload).map_err(GetAssertionError::InvalidCbor)?;
        Self::decode_value(value)
    }

    pub fn decode_value(value: CborValue) -> Result<Self, GetAssertionError> {
        let CborValue::Map(entries) = value else {
            return Err(GetAssertionError::UnexpectedType(0));
        };
        let mut rp_id = None;
        let mut client_data_hash = None;
        let mut allow_list = None;
        let mut options = None;
        let mut hmac_secret = None;
        let mut large_blob_key = false;
        let mut get_cred_blob = false;
        let mut extensions_seen = false;
        for (key, value) in entries {
            let CborValue::Unsigned(key) = key else {
                continue;
            };
            match key {
                1 => {
                    if rp_id.is_some() {
                        return Err(GetAssertionError::InvalidParameter(1));
                    }
                    let CborValue::Text(value) = value else {
                        return Err(GetAssertionError::UnexpectedType(1));
                    };
                    if value.is_empty() {
                        return Err(GetAssertionError::InvalidParameter(1));
                    }
                    rp_id = Some(value);
                }
                2 => {
                    if client_data_hash.is_some() {
                        return Err(GetAssertionError::InvalidParameter(2));
                    }
                    let CborValue::Bytes(value) = value else {
                        return Err(GetAssertionError::UnexpectedType(2));
                    };
                    let hash: [u8; 32] = value
                        .try_into()
                        .map_err(|_| GetAssertionError::InvalidParameter(2))?;
                    client_data_hash = Some(hash);
                }
                3 => {
                    if allow_list.is_some() {
                        return Err(GetAssertionError::InvalidParameter(3));
                    }
                    let CborValue::Array(descriptors) = value else {
                        return Err(GetAssertionError::UnexpectedType(3));
                    };
                    allow_list = Some(parse_credential_descriptors(descriptors, 3)?);
                }
                4 => {
                    if extensions_seen {
                        return Err(GetAssertionError::InvalidParameter(4));
                    }
                    extensions_seen = true;
                    let parsed = parse_hmac_secret_assertion(value)?;
                    hmac_secret = parsed.0;
                    large_blob_key = parsed.1;
                    get_cred_blob = parsed.2;
                }
                5 => {
                    if options.is_some() {
                        return Err(GetAssertionError::InvalidParameter(5));
                    }
                    options = Some(parse_get_assertion_options(value)?);
                }
                _ => {}
            }
        }
        Ok(Self {
            rp_id: rp_id.ok_or(GetAssertionError::MissingParameter(1))?,
            client_data_hash: client_data_hash.ok_or(GetAssertionError::MissingParameter(2))?,
            allow_list,
            options: options.unwrap_or_default(),
            hmac_secret,
            large_blob_key,
            get_cred_blob,
        })
    }

    #[must_use]
    pub fn rp_id_hash(&self) -> RpIdHash {
        Sha256::digest(self.rp_id.as_bytes()).into()
    }

    #[must_use]
    pub fn find_credentials<'a>(&self, store: &'a CredentialStore) -> Vec<&'a CredentialRecord> {
        store.find_for_assertion(self.rp_id_hash(), self.allow_list.as_deref())
    }
}

fn parse_hmac_secret_assertion(
    value: CborValue,
) -> Result<(Option<HmacSecretInput>, bool, bool), GetAssertionError> {
    let CborValue::Map(entries) = value else {
        return Err(GetAssertionError::UnexpectedType(4));
    };
    let mut secret_value = None;
    let mut large_blob_key = false;
    let mut get_cred_blob = false;
    let mut cred_blob_seen = false;
    for (key, value) in entries {
        if key == CborValue::Text("hmac-secret".into()) {
            if secret_value.is_some() {
                return Err(GetAssertionError::InvalidParameter(4));
            }
            secret_value = Some(value);
        } else if key == CborValue::Text("largeBlobKey".into()) {
            if large_blob_key || value != CborValue::Bool(true) {
                return Err(GetAssertionError::InvalidOption);
            }
            large_blob_key = true;
        } else if key == CborValue::Text("credBlob".into()) {
            if cred_blob_seen {
                return Err(GetAssertionError::InvalidParameter(4));
            }
            let CborValue::Bool(requested) = value else {
                return Err(GetAssertionError::UnexpectedType(4));
            };
            cred_blob_seen = true;
            get_cred_blob = requested;
        }
    }
    let Some(secret_value) = secret_value else {
        return Ok((None, large_blob_key, get_cred_blob));
    };
    let CborValue::Map(fields) = secret_value else {
        return Err(GetAssertionError::UnexpectedType(4));
    };
    let mut key_agreement = None;
    let mut salt_enc = None;
    let mut salt_auth = None;
    let mut pin_uv_auth_protocol = None;
    for (key, value) in fields {
        let CborValue::Unsigned(key) = key else {
            continue;
        };
        let slot = match key {
            1 => &mut key_agreement,
            2 => &mut salt_enc,
            3 => &mut salt_auth,
            4 => &mut pin_uv_auth_protocol,
            _ => continue,
        };
        if slot.is_some() {
            return Err(GetAssertionError::InvalidParameter(4));
        }
        *slot = Some(value);
    }
    let CborValue::Map(key_agreement) =
        key_agreement.ok_or(GetAssertionError::MissingParameter(4))?
    else {
        return Err(GetAssertionError::UnexpectedType(4));
    };
    let CborValue::Bytes(salt_enc) = salt_enc.ok_or(GetAssertionError::MissingParameter(4))? else {
        return Err(GetAssertionError::UnexpectedType(4));
    };
    let CborValue::Bytes(salt_auth) = salt_auth.ok_or(GetAssertionError::MissingParameter(4))?
    else {
        return Err(GetAssertionError::UnexpectedType(4));
    };
    let protocol = match pin_uv_auth_protocol {
        None => 1,
        Some(CborValue::Unsigned(value @ (1 | 2))) => value,
        Some(CborValue::Unsigned(_)) => return Err(GetAssertionError::InvalidParameter(4)),
        Some(_) => return Err(GetAssertionError::UnexpectedType(4)),
    };
    let block_iv = if protocol == 2 { 16 } else { 0 };
    let auth_size = if protocol == 2 { 32 } else { 16 };
    if !matches!(salt_enc.len(), value if value == 32 + block_iv || value == 64 + block_iv)
        || salt_auth.len() != auth_size
    {
        return Err(GetAssertionError::InvalidParameter(4));
    }
    Ok((
        Some(HmacSecretInput {
            key_agreement: CborValue::Map(key_agreement),
            salt_enc,
            salt_auth,
            pin_uv_auth_protocol: protocol,
        }),
        large_blob_key,
        get_cred_blob,
    ))
}

fn parse_get_assertion_options(value: CborValue) -> Result<GetAssertionOptions, GetAssertionError> {
    let CborValue::Map(entries) = value else {
        return Err(GetAssertionError::UnexpectedType(5));
    };
    let mut options = GetAssertionOptions::default();
    for (key, value) in entries {
        let CborValue::Text(key) = key else {
            continue;
        };
        let slot = match key.as_str() {
            "up" => &mut options.user_presence,
            "uv" => &mut options.user_verification,
            _ => continue,
        };
        if slot.is_some() {
            return Err(GetAssertionError::InvalidParameter(5));
        }
        let CborValue::Bool(value) = value else {
            return Err(GetAssertionError::UnexpectedType(5));
        };
        *slot = Some(value);
    }
    Ok(options)
}

fn parse_credential_descriptors(
    descriptors: Vec<CborValue>,
    parameter: u64,
) -> Result<Vec<Vec<u8>>, GetAssertionError> {
    descriptors
        .into_iter()
        .map(|descriptor| {
            let CborValue::Map(fields) = descriptor else {
                return Err(GetAssertionError::UnexpectedType(parameter));
            };
            let mut credential_type = None;
            let mut id = None;
            for (key, value) in fields {
                let CborValue::Text(key) = key else {
                    continue;
                };
                match key.as_str() {
                    "type" => {
                        if credential_type.is_some() {
                            return Err(GetAssertionError::InvalidParameter(parameter));
                        }
                        let CborValue::Text(value) = value else {
                            return Err(GetAssertionError::UnexpectedType(parameter));
                        };
                        if value != "public-key" {
                            return Err(GetAssertionError::InvalidParameter(parameter));
                        }
                        credential_type = Some(());
                    }
                    "id" => {
                        if id.is_some() {
                            return Err(GetAssertionError::InvalidParameter(parameter));
                        }
                        let CborValue::Bytes(value) = value else {
                            return Err(GetAssertionError::UnexpectedType(parameter));
                        };
                        if value.is_empty() {
                            return Err(GetAssertionError::InvalidParameter(parameter));
                        }
                        id = Some(value);
                    }
                    _ => {}
                }
            }
            if credential_type.is_none() || id.is_none() {
                return Err(GetAssertionError::UnexpectedType(parameter));
            }
            Ok(id.expect("validated above"))
        })
        .collect()
}

impl Ctap2Response {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        encode_response(self.status, &self.payload)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetInfoProfile {
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    pub aaguid: [u8; 16],
    pub options: Vec<(String, bool)>,
    pub max_msg_size: u64,
    pub pin_uv_auth_protocols: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetInfoError {
    MissingVersion,
    InvalidMessageSize,
    CborEncoding(CborError),
}

impl From<CborError> for GetInfoError {
    fn from(error: CborError) -> Self {
        Self::CborEncoding(error)
    }
}

/// Encodes GetInfo responses from an explicitly configured authenticator profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetInfoHandler {
    get_info_payload: Vec<u8>,
}

impl GetInfoHandler {
    pub fn new(profile: &GetInfoProfile) -> Result<Self, GetInfoError> {
        Ok(Self {
            get_info_payload: encode_get_info(profile)?,
        })
    }

    #[must_use]
    pub fn handle(&self, request_payload: &[u8]) -> Ctap2Response {
        if request_payload.is_empty() {
            Ctap2Response {
                status: Ctap2Status::Success,
                payload: self.get_info_payload.clone(),
            }
        } else {
            Ctap2Response::error(Ctap2Status::InvalidLength)
        }
    }
}

pub fn encode_get_info(profile: &GetInfoProfile) -> Result<Vec<u8>, GetInfoError> {
    if profile.versions.is_empty() {
        return Err(GetInfoError::MissingVersion);
    }
    if profile.max_msg_size == 0 {
        return Err(GetInfoError::InvalidMessageSize);
    }
    let versions = profile
        .versions
        .iter()
        .cloned()
        .map(CborValue::Text)
        .collect();
    let extensions = profile
        .extensions
        .iter()
        .cloned()
        .map(CborValue::Text)
        .collect();
    let options = profile
        .options
        .iter()
        .map(|(key, value)| (CborValue::Text(key.clone()), CborValue::Bool(*value)))
        .collect();
    let mut fields = vec![
        (CborValue::Unsigned(1), CborValue::Array(versions)),
        (CborValue::Unsigned(2), CborValue::Array(extensions)),
        (
            CborValue::Unsigned(3),
            CborValue::Bytes(profile.aaguid.to_vec()),
        ),
        (CborValue::Unsigned(4), CborValue::Map(options)),
        (
            CborValue::Unsigned(5),
            CborValue::Unsigned(profile.max_msg_size),
        ),
    ];
    if !profile.pin_uv_auth_protocols.is_empty() {
        fields.push((
            CborValue::Unsigned(6),
            CborValue::Array(
                profile
                    .pin_uv_auth_protocols
                    .iter()
                    .copied()
                    .map(CborValue::Unsigned)
                    .collect(),
            ),
        ));
    }
    if profile
        .options
        .iter()
        .any(|(name, enabled)| name == "largeBlobs" && *enabled)
    {
        fields.push((
            CborValue::Unsigned(0x0b),
            CborValue::Unsigned(crate::credentials::MAX_SERIALIZED_LARGE_BLOB_ARRAY as u64),
        ));
    }
    if profile
        .extensions
        .iter()
        .any(|extension| extension == "credBlob")
    {
        fields.push((
            CborValue::Unsigned(0x0f),
            CborValue::Unsigned(MAX_CREDENTIAL_BLOB_LENGTH as u64),
        ));
    }
    Ok(encode(&CborValue::Map(fields))?)
}
