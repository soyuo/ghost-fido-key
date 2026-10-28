//! Minimal CTAP2 command and status boundary.

use crate::cbor::{CborError, CborValue, decode, encode};

use core::fmt;

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
    InvalidCbor = 0x12,
    MissingParameter = 0x14,
    UnsupportedOption = 0x2e,
    NoCredentials = 0x31,
    UserActionPending = 0x32,
    RequestTooLarge = 0x39,
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
    pub command: Ctap2Command,
    pub payload: Vec<u8>,
}

impl Ctap2Request {
    pub fn decode(bytes: &[u8]) -> Result<Self, Ctap2Error> {
        let (&command, payload) = bytes.split_first().ok_or(Ctap2Error::EmptyRequest)?;
        let command = command.try_into()?;
        if !payload.is_empty() {
            decode(payload).map_err(Ctap2Error::InvalidCbor)?;
        }
        Ok(Self {
            command,
            payload: payload.to_vec(),
        })
    }
}

#[must_use]
pub fn encode_response(status: Ctap2Status, payload: &[u8]) -> Vec<u8> {
    let mut response = Vec::with_capacity(payload.len() + 1);
    response.push(status.wire());
    response.extend_from_slice(payload);
    response
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetInfoProfile {
    pub versions: Vec<String>,
    pub aaguid: [u8; 16],
    pub options: Vec<(String, bool)>,
    pub max_msg_size: u64,
    pub pin_uv_auth_protocols: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetInfoError {
    MissingVersion,
    InvalidMessageSize,
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
    let options = profile
        .options
        .iter()
        .map(|(key, value)| (CborValue::Text(key.clone()), CborValue::Bool(*value)))
        .collect();
    Ok(encode(&CborValue::Map(vec![
        (CborValue::Unsigned(1), CborValue::Array(versions)),
        (
            CborValue::Unsigned(3),
            CborValue::Bytes(profile.aaguid.to_vec()),
        ),
        (CborValue::Unsigned(4), CborValue::Map(options)),
        (
            CborValue::Unsigned(5),
            CborValue::Unsigned(profile.max_msg_size),
        ),
        (
            CborValue::Unsigned(6),
            CborValue::Array(
                profile
                    .pin_uv_auth_protocols
                    .iter()
                    .copied()
                    .map(CborValue::Unsigned)
                    .collect(),
            ),
        ),
    ])))
}
