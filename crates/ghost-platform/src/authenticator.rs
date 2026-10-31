//! CTAP2 command routing across the platform-independent core and providers.

use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use ghost_fido_core::{
    CborValue, CredentialError, CredentialId, CredentialStore, Ctap2Command, Ctap2Request,
    Ctap2Response, Ctap2Status, GetAssertionRequest, GetInfoError, GetInfoHandler, GetInfoProfile,
    MAX_RP_IDS_FOR_MIN_PIN_LENGTH, MAX_SERIALIZED_LARGE_BLOB_ARRAY, MakeCredentialRequest,
    PIN_ENCRYPTED_SIZE, PIN_HASH_SIZE, PIN_UV_AUTH_PROTOCOL, PIN_UV_AUTH_PROTOCOL_TWO,
    PinKeyAgreement, PinUvAuthProtocol, PinUvAuthSharedSecret, client_pin_hash, decode_cbor,
    encode_cbor,
};

const PIN_PROTOCOL_TIMEOUT: Duration = Duration::from_secs(30);
const PIN_UV_PERMISSION_LARGE_BLOB_WRITE: u8 = 0x10;
const PIN_UV_PERMISSION_AUTHENTICATOR_CONFIG: u8 = 0x20;

use crate::{
    GetAssertionExecutionError, KeyCreationPolicy, KeyReference, KeyStore,
    MakeCredentialExecutionError, PlatformErrorKind, SoftwareKeyConsent, UserVerification,
    VerificationAction, VerificationDecision, VerificationRequest,
    execute_next_assertion_with_uv_and_hmac_secret,
};

const ASSERTION_CONTINUATION_TIMEOUT: Duration = Duration::from_secs(30);
const CREDENTIAL_MANAGEMENT_TIMEOUT: Duration = Duration::from_secs(30);
const LARGE_BLOB_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CREDENTIAL_MANAGEMENT_CHANNELS: usize = 8;
const RESET_POWER_UP_WINDOW: Duration = Duration::from_secs(10);
const LEGACY_CHANNEL: u32 = u32::MAX;

/// Credential Management authorization failures use CTAP's PIN-auth-invalid status.
fn credential_management_auth_status(status: Ctap2Status) -> Ctap2Status {
    if status == Ctap2Status::UnauthorizedPermission {
        Ctap2Status::PinAuthInvalid
    } else {
        status
    }
}

struct AssertionContinuation {
    request: GetAssertionRequest,
    credentials: VecDeque<CredentialId>,
    expires_at: Instant,
    pin_uv_auth_token_expires_at: Option<Instant>,
    user_verified: bool,
    hmac_secret_shared_secret: Option<PinUvAuthSharedSecret>,
}

impl Drop for AssertionContinuation {
    fn drop(&mut self) {
        self.hmac_secret_shared_secret = None;
    }
}

struct CredentialManagementContinuation {
    expires_at: Instant,
    pin_uv_auth_token_expires_at: Option<Instant>,
    position: usize,
    entries: CredentialManagementEntries,
}

struct LargeBlobWriteState {
    expected_length: usize,
    bytes: Zeroizing<Vec<u8>>,
    expires_at: Instant,
    pin_uv_auth_token_expires_at: Option<Instant>,
}

impl Drop for LargeBlobWriteState {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

enum CredentialManagementEntries {
    RelyingParties(Vec<(String, [u8; 32], u64)>),
    Credentials {
        records: Vec<ghost_fido_core::CredentialRecord>,
    },
}

#[derive(Debug, Clone)]
pub struct AuthenticatorServiceConfig {
    pub get_info: GetInfoProfile,
    pub aaguid: [u8; 16],
    pub key_creation_policy: KeyCreationPolicy,
    pub software_key_consent: Option<SoftwareKeyConsent>,
    pub request_timeout: Duration,
}

#[derive(Debug)]
pub enum AuthenticatorServiceError {
    MakeCredential(MakeCredentialExecutionError),
    GetAssertion(GetAssertionExecutionError),
}

/// Routes decoded CTAP2 requests through the configured credential and platform providers.
pub struct AuthenticatorService<'a> {
    store: &'a mut CredentialStore,
    key_store: &'a dyn KeyStore,
    verification: &'a dyn UserVerification,
    config: AuthenticatorServiceConfig,
    assertion_continuations: BTreeMap<u32, AssertionContinuation>,
    credential_management: BTreeMap<u32, CredentialManagementContinuation>,
    large_blob_writes: BTreeMap<u32, LargeBlobWriteState>,
    client_pin: ClientPinHandler,
    started_at: Instant,
}

#[derive(Default)]
struct ClientPinHandler {
    agreements: BTreeMap<u32, PinAgreementEntry>,
    tokens: BTreeMap<u32, PinTokenEntry>,
    consecutive_pin_mismatches: u8,
    power_cycle_required: bool,
    pending_pin_retries: Option<u8>,
}

struct PinAgreementEntry {
    key: PinKeyAgreement,
    protocol: PinUvAuthProtocol,
    expires_at: Instant,
}

struct PinTokenEntry {
    value: [u8; 32],
    protocol: PinUvAuthProtocol,
    expires_at: Instant,
    permissions: u8,
    relying_party_hash: Option<[u8; 32]>,
}

impl Drop for PinTokenEntry {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl ClientPinHandler {
    fn clear_all(&mut self) {
        self.agreements.clear();
        self.tokens.clear();
    }

    fn clear_user_presence_permissions(&mut self, channel: u32) {
        if let Some(token) = self.tokens.get_mut(&channel) {
            token.permissions &= PIN_UV_PERMISSION_LARGE_BLOB_WRITE;
        }
    }

    fn token_expiration(&self, channel: u32) -> Option<Instant> {
        self.tokens.get(&channel).map(|token| token.expires_at)
    }

    fn expire(&mut self) {
        let now = Instant::now();
        self.agreements.retain(|_, entry| now < entry.expires_at);
        self.tokens.retain(|_, entry| now < entry.expires_at);
    }

    fn authorize(
        &mut self,
        channel: u32,
        message: &[u8],
        auth: &[u8],
        protocol: PinUvAuthProtocol,
        permission: u8,
        relying_party_id: Option<&str>,
    ) -> Result<(), Ctap2Status> {
        let relying_party_hash =
            relying_party_id.map(|rp_id| Sha256::digest(rp_id.as_bytes()).into());
        self.authorize_rp_hash(
            channel,
            message,
            auth,
            protocol,
            permission,
            relying_party_hash,
        )
    }

    fn authorize_rp_hash(
        &mut self,
        channel: u32,
        message: &[u8],
        auth: &[u8],
        protocol: PinUvAuthProtocol,
        permission: u8,
        relying_party_hash: Option<[u8; 32]>,
    ) -> Result<(), Ctap2Status> {
        self.expire();
        if self
            .tokens
            .get(&channel)
            .is_some_and(|token| Instant::now() >= token.expires_at)
        {
            self.tokens.remove(&channel);
            return Err(Ctap2Status::PinUvAuthTokenRequired);
        }
        let token = self
            .tokens
            .get_mut(&channel)
            .ok_or(Ctap2Status::PinUvAuthTokenRequired)?;
        if token.protocol != protocol
            || !protocol.verify_token_authentication(&token.value, message, auth)
        {
            return Err(Ctap2Status::PinAuthInvalid);
        }
        if token.permissions & permission == 0 {
            return Err(Ctap2Status::UnauthorizedPermission);
        }
        if let Some(allowed_hash) = token.relying_party_hash {
            if Some(allowed_hash) != relying_party_hash {
                return Err(Ctap2Status::UnauthorizedPermission);
            }
        } else if permission & 0x03 != 0 {
            let Some(relying_party_hash) = relying_party_hash else {
                return Err(Ctap2Status::UnauthorizedPermission);
            };
            // Legacy getPinToken grants default permissions before an RP is known.
            // Bind that token to the first MakeCredential/GetAssertion RP it authorizes.
            token.relying_party_hash = Some(relying_party_hash);
        }
        Ok(())
    }

    fn authorize_permission(
        &mut self,
        channel: u32,
        message: &[u8],
        auth: &[u8],
        protocol: PinUvAuthProtocol,
        permission: u8,
    ) -> Result<Instant, Ctap2Status> {
        self.expire();
        let token = self
            .tokens
            .get(&channel)
            .ok_or(Ctap2Status::PinUvAuthTokenRequired)?;
        if Instant::now() >= token.expires_at {
            self.tokens.remove(&channel);
            return Err(Ctap2Status::PinUvAuthTokenRequired);
        }
        if token.protocol != protocol
            || !protocol.verify_token_authentication(&token.value, message, auth)
        {
            return Err(Ctap2Status::PinAuthInvalid);
        }
        if token.permissions & permission == 0 {
            return Err(Ctap2Status::UnauthorizedPermission);
        }
        Ok(token.expires_at)
    }

    fn clear_channel(&mut self, channel: u32) {
        self.agreements.remove(&channel);
        self.tokens.remove(&channel);
    }

    fn handle(
        &mut self,
        channel: u32,
        value: Option<CborValue>,
        store: &mut CredentialStore,
    ) -> Ctap2Response {
        let Some(CborValue::Map(fields)) = value else {
            return Ctap2Response::error(Ctap2Status::CborUnexpectedType);
        };
        if fields
            .iter()
            .enumerate()
            .any(|(index, (key, _))| fields[..index].iter().any(|(previous, _)| previous == key))
        {
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        }
        let subcommand = match field(&fields, 2) {
            None => return Ctap2Response::error(Ctap2Status::MissingParameter),
            Some(CborValue::Unsigned(number)) => *number,
            Some(_) => return Ctap2Response::error(Ctap2Status::CborUnexpectedType),
        };
        if !matches!(subcommand, 1 | 2 | 3 | 4 | 5 | 9) {
            return Ctap2Response::error(Ctap2Status::InvalidSubcommand);
        }
        if self.power_cycle_required && subcommand != 1 {
            return Ctap2Response::error(Ctap2Status::PinAuthBlocked);
        }
        if let Err(status) = validate_pin_parameter_types(&fields, subcommand) {
            return Ctap2Response::error(status);
        }
        let protocol = match field(&fields, 1) {
            None => PinUvAuthProtocol::One,
            Some(CborValue::Unsigned(id)) => {
                let Some(protocol) = PinUvAuthProtocol::from_id(*id) else {
                    return Ctap2Response::error(Ctap2Status::InvalidParameter);
                };
                protocol
            }
            Some(_) => return Ctap2Response::error(Ctap2Status::CborUnexpectedType),
        };
        if subcommand > 2 && uint_field(&fields, 1).is_none() {
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        }
        if !store.has_protected_storage() {
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        }
        if let Some(retries) = self.pending_pin_retries {
            match store.set_pin_retries(retries) {
                Ok(()) => {
                    self.pending_pin_retries = None;
                    if retries == 0 {
                        self.power_cycle_required = false;
                        if subcommand != 1 {
                            return Ctap2Response::error(Ctap2Status::PinBlocked);
                        }
                    } else if self.power_cycle_required && subcommand != 1 {
                        return Ctap2Response::error(Ctap2Status::PinAuthBlocked);
                    }
                }
                Err(_) if subcommand != 1 => {
                    return Ctap2Response::error(Ctap2Status::Other);
                }
                Err(_) => {}
            }
        }
        match subcommand {
            1 => {
                let retries = self
                    .pending_pin_retries
                    .unwrap_or_else(|| store.pin_state().retries());
                let mut fields = vec![(3, CborValue::Unsigned(u64::from(retries)))];
                if self.power_cycle_required {
                    fields.push((4, CborValue::Bool(true)));
                }
                response_map(fields)
            }
            2 => {
                let agreement = match PinKeyAgreement::generate() {
                    Ok(agreement) => agreement,
                    Err(_) => return Ctap2Response::error(Ctap2Status::Other),
                };
                let cose_public_key = match agreement.cose_public_key() {
                    Ok(public_key) => public_key,
                    Err(_) => return Ctap2Response::error(Ctap2Status::Other),
                };
                let public_key = match decode_cbor(&cose_public_key) {
                    Ok(value) => value,
                    Err(_) => return Ctap2Response::error(Ctap2Status::Other),
                };
                self.agreements.insert(
                    channel,
                    PinAgreementEntry {
                        key: agreement,
                        protocol,
                        expires_at: Instant::now() + PIN_PROTOCOL_TIMEOUT,
                    },
                );
                response_map(vec![(1, public_key)])
            }
            3 => self.set_pin(channel, &fields, store),
            4 => self.change_pin(channel, &fields, store),
            5 => self.get_pin_token(channel, &fields, store),
            9 => self.get_pin_token_with_permissions(channel, &fields, store),
            _ => Ctap2Response::error(Ctap2Status::InvalidSubcommand),
        }
    }

    fn handle_config(
        &mut self,
        channel: u32,
        value: Option<CborValue>,
        store: &mut CredentialStore,
        always_uv: bool,
    ) -> Ctap2Response {
        let Some(CborValue::Map(fields)) = value else {
            return Ctap2Response::error(Ctap2Status::CborUnexpectedType);
        };
        if has_duplicate_cbor_keys(&fields) {
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        }
        let subcommand = match field(&fields, 1) {
            Some(CborValue::Unsigned(subcommand)) => *subcommand,
            Some(_) => return Ctap2Response::error(Ctap2Status::CborUnexpectedType),
            None => return Ctap2Response::error(Ctap2Status::MissingParameter),
        };
        let Ok(subcommand) = u8::try_from(subcommand) else {
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        };
        if subcommand != 3 {
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        }

        let params = match field(&fields, 2) {
            Some(CborValue::Map(params)) => Some(params),
            Some(_) => return Ctap2Response::error(Ctap2Status::CborUnexpectedType),
            None => None,
        };
        if params.is_some_and(|params| has_duplicate_cbor_keys(params)) {
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        }
        let params_fields = params.cloned().unwrap_or_default();
        let auth = match field(&fields, 4) {
            Some(CborValue::Bytes(auth)) => Some(auth.as_slice()),
            Some(_) => return Ctap2Response::error(Ctap2Status::CborUnexpectedType),
            None => None,
        };
        let protocol_id = match field(&fields, 3) {
            Some(CborValue::Unsigned(value)) => match u8::try_from(*value) {
                Ok(value) => Some(value),
                Err(_) => return Ctap2Response::error(Ctap2Status::InvalidParameter),
            },
            Some(_) => return Ctap2Response::error(Ctap2Status::CborUnexpectedType),
            None => None,
        };
        let auth_required = store.pin_state().verifier().is_some() || always_uv;
        if auth_required && auth.is_none() {
            return Ctap2Response::error(Ctap2Status::PinUvAuthTokenRequired);
        }
        if auth_required && auth.is_some() != protocol_id.is_some() {
            return Ctap2Response::error(if auth.is_some() {
                Ctap2Status::MissingParameter
            } else {
                Ctap2Status::InvalidParameter
            });
        }
        if auth_required {
            if let (Some(auth), Some(protocol_id)) = (auth, protocol_id) {
                let Some(protocol) = PinUvAuthProtocol::from_id(u64::from(protocol_id)) else {
                    return Ctap2Response::error(Ctap2Status::InvalidParameter);
                };
                if auth.len() != protocol.auth_parameter_size() {
                    return Ctap2Response::error(Ctap2Status::InvalidParameter);
                }
                let params_value = CborValue::Map(params_fields.clone());
                let encoded_params = if params.is_some() {
                    match encode_cbor(&params_value) {
                        Ok(encoded) => encoded,
                        Err(_) => return Ctap2Response::error(Ctap2Status::Other),
                    }
                } else {
                    Vec::new()
                };
                let mut message = Vec::with_capacity(34 + encoded_params.len());
                message.extend_from_slice(&[0xff; 32]);
                message.extend_from_slice(&[0x0d, subcommand]);
                message.extend_from_slice(&encoded_params);
                if self
                    .authorize_permission(
                        channel,
                        &message,
                        auth,
                        protocol,
                        PIN_UV_PERMISSION_AUTHENTICATOR_CONFIG,
                    )
                    .is_err()
                {
                    return Ctap2Response::error(Ctap2Status::PinAuthInvalid);
                }
            }
        }

        if field(&params_fields, 4).is_some() {
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        }
        let new_min_pin_length = match field(&params_fields, 1) {
            Some(CborValue::Unsigned(value)) => match u8::try_from(*value) {
                Ok(value) => Some(value),
                Err(_) => return Ctap2Response::error(Ctap2Status::InvalidParameter),
            },
            Some(_) => return Ctap2Response::error(Ctap2Status::CborUnexpectedType),
            None => None,
        };
        let min_pin_length_rp_ids = match field(&params_fields, 2) {
            Some(CborValue::Array(values)) => {
                if values.len() > MAX_RP_IDS_FOR_MIN_PIN_LENGTH {
                    return Ctap2Response::error(Ctap2Status::InvalidParameter);
                }
                let mut rp_ids = Vec::with_capacity(values.len());
                for value in values {
                    let CborValue::Text(rp_id) = value else {
                        return Ctap2Response::error(Ctap2Status::CborUnexpectedType);
                    };
                    if rp_id.is_empty()
                        || rp_id.len() > 253
                        || rp_ids.iter().any(|existing| existing == rp_id)
                    {
                        return Ctap2Response::error(Ctap2Status::InvalidParameter);
                    }
                    rp_ids.push(rp_id.clone());
                }
                Some(rp_ids)
            }
            Some(_) => return Ctap2Response::error(Ctap2Status::CborUnexpectedType),
            None => None,
        };
        let force_pin_change = match field(&params_fields, 3) {
            Some(CborValue::Bool(value)) => *value,
            Some(_) => return Ctap2Response::error(Ctap2Status::CborUnexpectedType),
            None => false,
        };
        if force_pin_change && store.pin_state().verifier().is_none() {
            return Ctap2Response::error(Ctap2Status::PinNotSet);
        }
        let min_pin_length = new_min_pin_length.unwrap_or(store.pin_state().min_pin_length());
        if min_pin_length < store.pin_state().min_pin_length() {
            return Ctap2Response::error(Ctap2Status::PinPolicyViolation);
        }

        match store.set_min_pin_policy(min_pin_length, min_pin_length_rp_ids, force_pin_change) {
            Ok(newly_forced) => {
                if newly_forced {
                    self.clear_all();
                }
                Ctap2Response {
                    status: Ctap2Status::Success,
                    payload: Vec::new(),
                }
            }
            Err(ghost_fido_core::CredentialError::InvalidPinState) => {
                Ctap2Response::error(Ctap2Status::InvalidParameter)
            }
            Err(_) => Ctap2Response::error(Ctap2Status::Other),
        }
    }

    fn record_pin_mismatch(&mut self, store: &mut CredentialStore) -> Ctap2Status {
        let retries = store.pin_state().retries().saturating_sub(1);
        self.consecutive_pin_mismatches = self.consecutive_pin_mismatches.saturating_add(1);
        self.pending_pin_retries = Some(retries);
        if store.set_pin_retries(retries).is_err() {
            if self.consecutive_pin_mismatches >= 3 {
                self.power_cycle_required = true;
            }
            return Ctap2Status::Other;
        }
        self.pending_pin_retries = None;
        if retries == 0 {
            return Ctap2Status::PinBlocked;
        }
        if self.consecutive_pin_mismatches >= 3 {
            self.power_cycle_required = true;
            return Ctap2Status::PinAuthBlocked;
        }
        Ctap2Status::PinInvalid
    }

    fn record_pin_success(&mut self, store: &mut CredentialStore) -> Result<(), Ctap2Status> {
        self.consecutive_pin_mismatches = 0;
        self.pending_pin_retries = Some(8);
        store.set_pin_retries(8).map_err(|_| Ctap2Status::Other)?;
        self.pending_pin_retries = None;
        Ok(())
    }

    fn shared_secret(
        &mut self,
        channel: u32,
        fields: &[(CborValue, CborValue)],
    ) -> Result<PinUvAuthSharedSecret, Ctap2Status> {
        let peer = field(fields, 3).ok_or(Ctap2Status::MissingParameter)?;
        if !matches!(peer, CborValue::Map(_)) {
            return Err(Ctap2Status::CborUnexpectedType);
        }
        let agreement = self
            .agreements
            .remove(&channel)
            .ok_or(Ctap2Status::PinAuthInvalid)?;
        let protocol = match field(fields, 1) {
            None => PinUvAuthProtocol::One,
            Some(CborValue::Unsigned(id)) => {
                PinUvAuthProtocol::from_id(*id).ok_or(Ctap2Status::InvalidParameter)?
            }
            Some(_) => return Err(Ctap2Status::CborUnexpectedType),
        };
        if protocol != agreement.protocol {
            return Err(Ctap2Status::PinAuthInvalid);
        }
        agreement
            .key
            .derive_shared_secret_for_protocol(peer, protocol)
            .map_err(|_| Ctap2Status::InvalidParameter)
    }

    fn hmac_secret_shared_secret(
        &mut self,
        channel: u32,
        peer: &CborValue,
        protocol: PinUvAuthProtocol,
    ) -> Result<PinUvAuthSharedSecret, Ctap2Status> {
        let agreement = self
            .agreements
            .remove(&channel)
            .ok_or(Ctap2Status::PinAuthInvalid)?;
        if agreement.protocol != protocol {
            return Err(Ctap2Status::PinAuthInvalid);
        }
        agreement
            .key
            .derive_shared_secret_for_protocol(peer, protocol)
            .map_err(|_| Ctap2Status::PinAuthInvalid)
    }

    fn set_pin(
        &mut self,
        channel: u32,
        fields: &[(CborValue, CborValue)],
        store: &mut CredentialStore,
    ) -> Ctap2Response {
        if store.pin_state().verifier().is_some() {
            return Ctap2Response::error(Ctap2Status::PinAuthInvalid);
        }
        let mut secret = match self.shared_secret(channel, fields) {
            Ok(secret) => secret,
            Err(status) => return Ctap2Response::error(status),
        };
        let (Some(auth), Some(encrypted)) = (byte_field(fields, 4), byte_field(fields, 5)) else {
            secret.zeroize();
            return Ctap2Response::error(Ctap2Status::MissingParameter);
        };
        if encrypted.len() != encrypted_size(PIN_ENCRYPTED_SIZE, secret.protocol())
            || !secret.verify(encrypted, auth)
        {
            secret.zeroize();
            return Ctap2Response::error(Ctap2Status::PinAuthInvalid);
        }
        let pin = ghost_fido_core::client_pin_decrypt_pin_with_protocol(&secret, encrypted);
        secret.zeroize();
        let Ok(pin) = pin else {
            return Ctap2Response::error(Ctap2Status::PinPolicyViolation);
        };
        let code_points = match pin_code_point_length(&pin) {
            Some(length) if length >= store.pin_state().min_pin_length() => length,
            _ => return Ctap2Response::error(Ctap2Status::PinPolicyViolation),
        };
        let verifier = client_pin_hash(&pin);
        match store.set_pin_verifier_with_length(Some(*verifier), Some(code_points)) {
            Ok(()) => Ctap2Response::error(Ctap2Status::Success),
            Err(_) => Ctap2Response::error(Ctap2Status::Other),
        }
    }

    fn change_pin(
        &mut self,
        channel: u32,
        fields: &[(CborValue, CborValue)],
        store: &mut CredentialStore,
    ) -> Ctap2Response {
        let Some(verifier) = store.pin_state().verifier().copied().map(Zeroizing::new) else {
            return Ctap2Response::error(Ctap2Status::PinNotSet);
        };
        if store.pin_state().retries() == 0 {
            return Ctap2Response::error(Ctap2Status::PinBlocked);
        }
        let mut secret = match self.shared_secret(channel, fields) {
            Ok(secret) => secret,
            Err(status) => return Ctap2Response::error(status),
        };
        let (Some(auth), Some(new_encrypted), Some(hash_encrypted)) = (
            byte_field(fields, 4),
            byte_field(fields, 5),
            byte_field(fields, 6),
        ) else {
            secret.zeroize();
            return Ctap2Response::error(Ctap2Status::MissingParameter);
        };
        if new_encrypted.len() != encrypted_size(PIN_ENCRYPTED_SIZE, secret.protocol())
            || hash_encrypted.len() != encrypted_size(PIN_HASH_SIZE, secret.protocol())
        {
            secret.zeroize();
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        }
        let mut authenticated = new_encrypted.to_vec();
        authenticated.extend_from_slice(hash_encrypted);
        if !secret.verify(&authenticated, auth) {
            secret.zeroize();
            return Ctap2Response::error(Ctap2Status::PinAuthInvalid);
        }
        let encrypted_hash = match secret.decrypt(hash_encrypted) {
            Ok(value) if value.len() == PIN_HASH_SIZE => value,
            _ => {
                secret.zeroize();
                return Ctap2Response::error(Ctap2Status::PinAuthInvalid);
            }
        };
        if encrypted_hash
            .as_slice()
            .ct_eq(verifier.as_slice())
            .unwrap_u8()
            != 1
        {
            secret.zeroize();
            return Ctap2Response::error(self.record_pin_mismatch(store));
        }
        if self.record_pin_success(store).is_err() {
            secret.zeroize();
            return Ctap2Response::error(Ctap2Status::Other);
        }
        let decrypted =
            ghost_fido_core::client_pin_decrypt_pin_with_protocol(&secret, new_encrypted);
        secret.zeroize();
        let Ok(pin) = decrypted else {
            return Ctap2Response::error(Ctap2Status::PinPolicyViolation);
        };
        let code_points = match pin_code_point_length(&pin) {
            Some(length) if length >= store.pin_state().min_pin_length() => length,
            _ => return Ctap2Response::error(Ctap2Status::PinPolicyViolation),
        };
        let new_verifier = client_pin_hash(&pin);
        if store.pin_state().force_pin_change()
            && new_verifier
                .as_slice()
                .ct_eq(verifier.as_slice())
                .unwrap_u8()
                == 1
        {
            return Ctap2Response::error(Ctap2Status::PinPolicyViolation);
        }
        match store.set_pin_verifier_with_length(Some(*new_verifier), Some(code_points)) {
            Ok(()) => {
                // CTAP requires a successful changePIN to revoke tokens on every channel.
                // Clearing drops each entry, whose Drop implementation zeroizes its token.
                self.tokens.clear();
                Ctap2Response::error(Ctap2Status::Success)
            }
            Err(_) => Ctap2Response::error(Ctap2Status::Other),
        }
    }

    fn get_pin_token(
        &mut self,
        channel: u32,
        fields: &[(CborValue, CborValue)],
        store: &mut CredentialStore,
    ) -> Ctap2Response {
        self.issue_pin_token(channel, fields, store, 0x03, None)
    }

    fn get_pin_token_with_permissions(
        &mut self,
        channel: u32,
        fields: &[(CborValue, CborValue)],
        store: &mut CredentialStore,
    ) -> Ctap2Response {
        if has_duplicate_field(fields, 9) || has_duplicate_field(fields, 10) {
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        }
        let Some(requested_permissions) = uint_field(fields, 9) else {
            return Ctap2Response::error(Ctap2Status::MissingParameter);
        };
        if requested_permissions == 0 {
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        }
        // CTAP ignores undefined permission bits, while defined but unsupported
        // permissions must still be rejected below.
        let permissions = (requested_permissions & 0x7f) as u8;
        if permissions
            & !(0x07 | PIN_UV_PERMISSION_LARGE_BLOB_WRITE | PIN_UV_PERMISSION_AUTHENTICATOR_CONFIG)
            != 0
        {
            return Ctap2Response::error(Ctap2Status::UnauthorizedPermission);
        }
        let relying_party_id = match field(fields, 10) {
            None => None,
            Some(CborValue::Text(value)) if !value.is_empty() => Some(value.clone()),
            Some(CborValue::Text(_)) => return Ctap2Response::error(Ctap2Status::InvalidParameter),
            Some(_) => return Ctap2Response::error(Ctap2Status::CborUnexpectedType),
        };
        if permissions & 0x03 != 0 && relying_party_id.is_none() {
            return Ctap2Response::error(Ctap2Status::MissingParameter);
        }
        self.issue_pin_token(channel, fields, store, permissions, relying_party_id)
    }

    fn issue_pin_token(
        &mut self,
        channel: u32,
        fields: &[(CborValue, CborValue)],
        store: &mut CredentialStore,
        permissions: u8,
        relying_party_id: Option<String>,
    ) -> Ctap2Response {
        let Some(verifier) = store.pin_state().verifier().copied().map(Zeroizing::new) else {
            return Ctap2Response::error(Ctap2Status::PinNotSet);
        };
        if store.pin_state().force_pin_change() {
            return Ctap2Response::error(Ctap2Status::PinPolicyViolation);
        }
        if store.pin_state().retries() == 0 {
            return Ctap2Response::error(Ctap2Status::PinBlocked);
        }
        let mut secret = match self.shared_secret(channel, fields) {
            Ok(secret) => secret,
            Err(status) => return Ctap2Response::error(status),
        };
        let (Some(auth), Some(encrypted)) = (byte_field(fields, 4), byte_field(fields, 6)) else {
            secret.zeroize();
            return Ctap2Response::error(Ctap2Status::MissingParameter);
        };
        if encrypted.len() != encrypted_size(PIN_HASH_SIZE, secret.protocol())
            || !secret.verify(encrypted, auth)
        {
            secret.zeroize();
            return Ctap2Response::error(Ctap2Status::PinAuthInvalid);
        }
        let decrypted_hash = match secret.decrypt(encrypted) {
            Ok(value) if value.len() == PIN_HASH_SIZE => value,
            _ => {
                secret.zeroize();
                return Ctap2Response::error(Ctap2Status::PinAuthInvalid);
            }
        };
        if decrypted_hash
            .as_slice()
            .ct_eq(verifier.as_slice())
            .unwrap_u8()
            != 1
        {
            secret.zeroize();
            return Ctap2Response::error(self.record_pin_mismatch(store));
        }
        if self.record_pin_success(store).is_err() {
            secret.zeroize();
            return Ctap2Response::error(Ctap2Status::Other);
        }
        let mut token = Zeroizing::new([0_u8; 32]);
        if getrandom::fill(&mut token[..]).is_err() {
            secret.zeroize();
            return Ctap2Response::error(Ctap2Status::Other);
        }
        let protocol = secret.protocol();
        let encrypted_token = match secret.encrypt(&token[..]) {
            Ok(value) => value,
            Err(_) => {
                secret.zeroize();
                return Ctap2Response::error(Ctap2Status::Other);
            }
        };
        secret.zeroize();
        // CTAP requires replacing the active authenticator token on successful
        // issuance, including tokens created on other channels or protocols.
        self.tokens.clear();
        // Keep a token copy only in the channel owner, which zeroizes it on drop.
        self.tokens.insert(
            channel,
            PinTokenEntry {
                value: *token,
                protocol,
                expires_at: Instant::now() + PIN_PROTOCOL_TIMEOUT,
                permissions,
                relying_party_hash: relying_party_id
                    .map(|rp_id| Sha256::digest(rp_id.as_bytes()).into()),
            },
        );
        response_map(vec![(2, CborValue::Bytes(encrypted_token.to_vec()))])
    }
}

fn field(fields: &[(CborValue, CborValue)], key: u64) -> Option<&CborValue> {
    fields
        .iter()
        .find(|(candidate, _)| *candidate == CborValue::Unsigned(key))
        .map(|(_, value)| value)
}

fn has_duplicate_cbor_keys(fields: &[(CborValue, CborValue)]) -> bool {
    fields
        .iter()
        .enumerate()
        .any(|(index, (key, _))| fields[..index].iter().any(|(previous, _)| previous == key))
}

fn pin_code_point_length(pin: &[u8]) -> Option<u8> {
    let pin = std::str::from_utf8(pin).ok()?;
    u8::try_from(pin.chars().count()).ok()
}

fn uint_field(fields: &[(CborValue, CborValue)], key: u64) -> Option<u64> {
    match field(fields, key) {
        Some(CborValue::Unsigned(value)) => Some(*value),
        _ => None,
    }
}

fn text_map_field<'a>(fields: &'a [(CborValue, CborValue)], key: &str) -> Option<&'a CborValue> {
    fields
        .iter()
        .find(|(candidate, _)| *candidate == CborValue::Text(key.to_owned()))
        .map(|(_, value)| value)
}

fn optional_text_field(
    fields: &[(CborValue, CborValue)],
    key: &str,
) -> Result<Option<String>, Ctap2Status> {
    match text_map_field(fields, key) {
        None => Ok(None),
        Some(CborValue::Text(value)) if value.len() <= 256 => Ok(Some(value.clone())),
        Some(CborValue::Text(_)) => Err(Ctap2Status::InvalidParameter),
        Some(_) => Err(Ctap2Status::CborUnexpectedType),
    }
}

fn rp_response(entry: &(String, [u8; 32], u64), total: u64) -> Ctap2Response {
    response_map(vec![
        (
            3,
            CborValue::Map(vec![(
                CborValue::Text("id".into()),
                CborValue::Text(entry.0.clone()),
            )]),
        ),
        (4, CborValue::Bytes(entry.1.to_vec())),
        (5, CborValue::Unsigned(total)),
    ])
}

fn user_entity(record: &ghost_fido_core::CredentialRecord) -> CborValue {
    let mut fields = vec![(
        CborValue::Text("id".into()),
        CborValue::Bytes(record.user_handle.clone()),
    )];
    if let Some(name) = &record.user_name {
        fields.push((
            CborValue::Text("name".into()),
            CborValue::Text(name.clone()),
        ));
    }
    if let Some(name) = &record.user_display_name {
        fields.push((
            CborValue::Text("displayName".into()),
            CborValue::Text(name.clone()),
        ));
    }
    CborValue::Map(fields)
}

fn byte_field(fields: &[(CborValue, CborValue)], key: u64) -> Option<&[u8]> {
    match field(fields, key) {
        Some(CborValue::Bytes(value)) => Some(value),
        _ => None,
    }
}

fn validate_pin_parameter_types(
    fields: &[(CborValue, CborValue)],
    subcommand: u64,
) -> Result<(), Ctap2Status> {
    let require_bytes = |key| match field(fields, key) {
        None => Err(Ctap2Status::MissingParameter),
        Some(CborValue::Bytes(_)) => Ok(()),
        Some(_) => Err(Ctap2Status::CborUnexpectedType),
    };
    let require_key_agreement = || match field(fields, 3) {
        None => Err(Ctap2Status::MissingParameter),
        Some(CborValue::Map(_)) => Ok(()),
        Some(_) => Err(Ctap2Status::CborUnexpectedType),
    };
    match subcommand {
        1 | 2 => Ok(()),
        3 => {
            require_key_agreement()?;
            require_bytes(4)?;
            require_bytes(5)
        }
        4 => {
            require_key_agreement()?;
            require_bytes(4)?;
            require_bytes(5)?;
            require_bytes(6)
        }
        5 => {
            if field(fields, 9).is_some() || field(fields, 10).is_some() {
                return Err(Ctap2Status::InvalidParameter);
            }
            require_key_agreement()?;
            require_bytes(4)?;
            require_bytes(6)
        }
        9 => {
            require_key_agreement()?;
            require_bytes(4)?;
            require_bytes(6)?;
            match field(fields, 9) {
                None => return Err(Ctap2Status::MissingParameter),
                Some(CborValue::Unsigned(_)) => {}
                Some(_) => return Err(Ctap2Status::CborUnexpectedType),
            }
            if matches!(field(fields, 10), Some(value) if !matches!(value, CborValue::Text(_))) {
                return Err(Ctap2Status::CborUnexpectedType);
            }
            Ok(())
        }
        _ => Err(Ctap2Status::InvalidParameter),
    }
}

fn response_map(fields: Vec<(u64, CborValue)>) -> Ctap2Response {
    let value = CborValue::Map(
        fields
            .into_iter()
            .map(|(key, value)| (CborValue::Unsigned(key), value))
            .collect(),
    );
    match encode_cbor(&value) {
        Ok(payload) => Ctap2Response {
            status: Ctap2Status::Success,
            payload,
        },
        Err(_) => Ctap2Response::error(Ctap2Status::Other),
    }
}

impl<'a> AuthenticatorService<'a> {
    pub fn new(
        store: &'a mut CredentialStore,
        key_store: &'a dyn KeyStore,
        verification: &'a dyn UserVerification,
        config: AuthenticatorServiceConfig,
    ) -> Result<Self, GetInfoError> {
        GetInfoHandler::new(&config.get_info)?;
        Ok(Self {
            store,
            key_store,
            verification,
            config,
            assertion_continuations: BTreeMap::new(),
            credential_management: BTreeMap::new(),
            large_blob_writes: BTreeMap::new(),
            client_pin: ClientPinHandler::default(),
            started_at: Instant::now(),
        })
    }

    pub fn handle(
        &mut self,
        request: &Ctap2Request,
    ) -> Result<Ctap2Response, AuthenticatorServiceError> {
        self.handle_on_channel(LEGACY_CHANNEL, request.clone())
    }

    /// Returns whether the credential store currently has a configured Client PIN.
    #[must_use]
    pub fn client_pin_is_configured(&self) -> bool {
        self.store.pin_state().verifier().is_some()
    }

    fn always_uv_enabled(&self) -> bool {
        self.config
            .get_info
            .options
            .iter()
            .any(|(name, enabled)| name == "alwaysUv" && *enabled)
    }

    /// Returns whether reset cleanup is pending in the credential store.
    #[must_use]
    pub fn reset_is_pending(&self) -> bool {
        self.store.reset_is_pending()
    }

    /// Returns whether provider-key cleanup is pending in the credential store.
    #[must_use]
    pub fn provider_key_cleanup_is_pending(&self) -> bool {
        self.store.provider_key_cleanup_pending()
    }

    /// Handles one CTAP2 request and scopes any GetNextAssertion state to its CTAPHID channel.
    pub fn handle_on_channel(
        &mut self,
        channel: u32,
        request: Ctap2Request,
    ) -> Result<Ctap2Response, AuthenticatorServiceError> {
        let (command, payload, decoded_payload) = request.into_parts();
        let refreshed_shared_state = match self.store.refresh_shared_state() {
            Ok(refreshed) => refreshed,
            Err(_) => return Ok(Ctap2Response::error(Ctap2Status::Other)),
        };
        if refreshed_shared_state {
            self.assertion_continuations.clear();
            self.credential_management.clear();
            self.large_blob_writes.clear();
            self.client_pin.clear_all();
        }
        let resumed_provider_cleanup = self.store.provider_key_cleanup_pending();
        if resumed_provider_cleanup && self.recover_pending_provider_key().is_err() {
            return Ok(Ctap2Response::error(Ctap2Status::Other));
        }
        let resumed_reset = self.store.reset_is_pending();
        if resumed_reset {
            self.large_blob_writes.clear();
        }
        if resumed_reset && self.recover_pending_reset().is_err() {
            return Ok(Ctap2Response::error(Ctap2Status::Other));
        }
        if resumed_reset && command == Ctap2Command::Reset {
            return Ok(Ctap2Response::error(Ctap2Status::Success));
        }
        if command != Ctap2Command::GetNextAssertion {
            self.assertion_continuations.remove(&channel);
        }
        if command != Ctap2Command::CredentialManagement {
            self.credential_management.remove(&channel);
        }
        self.client_pin.expire();
        let now = Instant::now();
        self.assertion_continuations.retain(|_, state| {
            now < state.expires_at
                && state
                    .pin_uv_auth_token_expires_at
                    .map_or(true, |expires_at| now < expires_at)
        });
        self.credential_management.retain(|_, state| {
            now < state.expires_at
                && state
                    .pin_uv_auth_token_expires_at
                    .map_or(true, |expires_at| now < expires_at)
        });
        self.large_blob_writes.retain(|_, state| {
            now < state.expires_at
                && state
                    .pin_uv_auth_token_expires_at
                    .map_or(true, |expires_at| now < expires_at)
        });
        if command != Ctap2Command::LargeBlobs {
            self.large_blob_writes.remove(&channel);
        }
        match command {
            Ctap2Command::GetInfo => {
                if !payload.is_empty() {
                    return Ok(Ctap2Response::error(Ctap2Status::InvalidLength));
                }
                let mut profile = self.config.get_info.clone();
                let always_uv = self.always_uv_enabled();
                if always_uv {
                    for (name, enabled) in &mut profile.options {
                        if name == "makeCredUvNotRqd" {
                            *enabled = false;
                        }
                    }
                }
                let pin_is_set = self.store.pin_state().verifier().is_some();
                let protected_storage_available = self.store.has_protected_storage();
                profile.min_pin_length =
                    protected_storage_available.then(|| self.store.pin_state().min_pin_length());
                profile.force_pin_change =
                    protected_storage_available && self.store.pin_state().force_pin_change();
                profile.max_rp_ids_for_set_min_pin_length =
                    protected_storage_available.then_some(MAX_RP_IDS_FOR_MIN_PIN_LENGTH as u8);
                let large_blobs_available =
                    self.store.supports_large_blobs() && profile.max_msg_size > 64;
                let credential_management_ready =
                    pin_is_set && self.ensure_credential_management_metadata();
                profile.versions.retain(|version| version != "FIDO_2_1");
                let mut client_pin_option_present = false;
                for (name, value) in &mut profile.options {
                    if name == "clientPin" {
                        *value = pin_is_set;
                        client_pin_option_present = true;
                    }
                }
                if !client_pin_option_present {
                    profile.options.push(("clientPin".into(), pin_is_set));
                }
                profile.options.retain(|(name, _)| name != "largeBlobs");
                profile
                    .options
                    .push(("largeBlobs".into(), large_blobs_available));
                profile
                    .options
                    .retain(|(name, _)| name != "setMinPINLength" && name != "authnrCfg");
                if protected_storage_available {
                    profile.options.push(("setMinPINLength".into(), true));
                    profile.options.push(("authnrCfg".into(), true));
                }
                for (name, value) in &mut profile.options {
                    if name == "pinUvAuthToken" {
                        *value = false;
                    }
                }
                if let Some((_, value)) = profile
                    .options
                    .iter_mut()
                    .find(|(name, _)| name == "credMgmt")
                {
                    *value = credential_management_ready;
                } else {
                    profile
                        .options
                        .push(("credMgmt".into(), credential_management_ready));
                }
                profile.extensions.retain(|extension| {
                    extension != "hmac-secret"
                        && extension != "credProtect"
                        && extension != "credBlob"
                        && extension != "largeBlobKey"
                        && extension != "minPinLength"
                });
                if protected_storage_available {
                    profile.extensions.push("hmac-secret".into());
                    profile.extensions.push("credProtect".into());
                    profile.extensions.push("credBlob".into());
                    profile.extensions.push("minPinLength".into());
                }
                if large_blobs_available {
                    profile.extensions.push("largeBlobKey".into());
                }
                profile.pin_uv_auth_protocols = if protected_storage_available {
                    vec![
                        u64::from(PIN_UV_AUTH_PROTOCOL_TWO),
                        u64::from(PIN_UV_AUTH_PROTOCOL),
                    ]
                } else {
                    Vec::new()
                };
                if protected_storage_available {
                    if let Some((_, value)) = profile
                        .options
                        .iter_mut()
                        .find(|(name, _)| name == "pinUvAuthToken")
                    {
                        *value = true;
                    } else {
                        profile.options.push(("pinUvAuthToken".into(), true));
                    }
                    let extensions_ready =
                        ["hmac-secret", "credProtect", "credBlob"]
                            .iter()
                            .all(|required| {
                                profile
                                    .extensions
                                    .iter()
                                    .any(|extension| extension == required)
                            });
                    if credential_management_ready
                        && extensions_ready
                        && profile.pin_uv_auth_protocols.contains(&2)
                        && !profile.versions.iter().any(|version| version == "FIDO_2_1")
                    {
                        profile.versions.push("FIDO_2_1".into());
                    }
                }
                match GetInfoHandler::new(&profile) {
                    Ok(handler) => Ok(handler.handle(&payload)),
                    Err(_) => Ok(Ctap2Response::error(Ctap2Status::Other)),
                }
            }
            Ctap2Command::MakeCredential => {
                let pin_auth = match parse_pin_auth(decoded_payload.as_ref(), 8, 9) {
                    Ok(value) => value,
                    Err(status) => return Ok(Ctap2Response::error(status)),
                };
                let typed = match decoded_payload.map_or_else(
                    || MakeCredentialRequest::decode(&payload),
                    MakeCredentialRequest::decode_value,
                ) {
                    Ok(request) => request,
                    Err(error) => return Ok(Ctap2Response::error(error.status())),
                };
                if typed.large_blob_key && !self.store.supports_large_blobs() {
                    return Ok(Ctap2Response::error(Ctap2Status::UnsupportedOption));
                }
                if typed.cred_blob.is_some() && !self.store.has_protected_storage() {
                    return Ok(Ctap2Response::error(Ctap2Status::UnsupportedOption));
                }
                if typed.min_pin_length && !self.store.has_protected_storage() {
                    return Ok(Ctap2Response::error(Ctap2Status::UnsupportedOption));
                }
                let (user_verified, _) = match self.verify_pin_authorization(
                    channel,
                    &typed.client_data_hash,
                    pin_auth,
                    typed.options.user_verification == Some(true),
                    self.always_uv_enabled(),
                    0x01,
                    &typed.rp.id,
                ) {
                    Ok(value) => value,
                    Err(status) => return Ok(Ctap2Response::error(status)),
                };
                let mut on_user_presence = || {
                    self.client_pin.clear_user_presence_permissions(channel);
                };
                crate::registration::register_make_credential_with_uv_and_presence_callback(
                    &typed,
                    self.store,
                    self.key_store,
                    self.verification,
                    self.config.key_creation_policy,
                    self.config.software_key_consent,
                    self.config.aaguid,
                    self.config.request_timeout,
                    user_verified,
                    &mut on_user_presence,
                )
                .map_err(AuthenticatorServiceError::MakeCredential)
            }
            Ctap2Command::GetAssertion => {
                let pin_auth = match parse_pin_auth(decoded_payload.as_ref(), 6, 7) {
                    Ok(value) => value,
                    Err(status) => return Ok(Ctap2Response::error(status)),
                };
                let typed = match decoded_payload.map_or_else(
                    || GetAssertionRequest::decode(&payload),
                    GetAssertionRequest::decode_value,
                ) {
                    Ok(request) => request,
                    Err(error) => return Ok(Ctap2Response::error(error.status())),
                };
                if typed.large_blob_key && !self.store.supports_large_blobs() {
                    return Ok(Ctap2Response::error(Ctap2Status::UnsupportedOption));
                }
                if typed.get_cred_blob && !self.store.has_protected_storage() {
                    return Ok(Ctap2Response::error(Ctap2Status::UnsupportedOption));
                }
                let mut hmac_secret_shared_secret = if let Some(input) = typed.hmac_secret.as_ref()
                {
                    let Some(protocol) = PinUvAuthProtocol::from_id(input.pin_uv_auth_protocol)
                    else {
                        return Ok(Ctap2Response::error(Ctap2Status::InvalidParameter));
                    };
                    match self.client_pin.hmac_secret_shared_secret(
                        channel,
                        &input.key_agreement,
                        protocol,
                    ) {
                        Ok(secret) => Some(secret),
                        Err(status) => return Ok(Ctap2Response::error(status)),
                    }
                } else {
                    None
                };
                let (user_verified, pin_uv_auth_token_expires_at) = match self
                    .verify_pin_authorization(
                        channel,
                        &typed.client_data_hash,
                        pin_auth,
                        typed.options.user_verification == Some(true),
                        self.always_uv_enabled(),
                        0x02,
                        &typed.rp_id,
                    ) {
                    Ok(value) => value,
                    Err(status) => {
                        if let Some(secret) = &mut hmac_secret_shared_secret {
                            secret.zeroize();
                        }
                        return Ok(Ctap2Response::error(status));
                    }
                };
                let mut on_user_presence = || {
                    self.client_pin.clear_user_presence_permissions(channel);
                };
                let execution = crate::assertion::execute_get_assertion_with_uv_and_hmac_secret_and_presence_callback(
                    &typed,
                    self.store,
                    self.key_store,
                    self.verification,
                    self.config.request_timeout,
                    user_verified,
                    hmac_secret_shared_secret.as_ref(),
                    &mut on_user_presence,
                )
                .map_err(AuthenticatorServiceError::GetAssertion)?;
                if !execution.remaining_credentials.is_empty() {
                    self.assertion_continuations.insert(
                        channel,
                        AssertionContinuation {
                            request: typed,
                            credentials: execution.remaining_credentials.into(),
                            expires_at: Instant::now() + ASSERTION_CONTINUATION_TIMEOUT,
                            user_verified,
                            pin_uv_auth_token_expires_at,
                            hmac_secret_shared_secret: hmac_secret_shared_secret.as_ref().cloned(),
                        },
                    );
                } else if let Some(secret) = &mut hmac_secret_shared_secret {
                    secret.zeroize();
                }
                Ok(execution.response)
            }
            Ctap2Command::GetNextAssertion => {
                if !payload.is_empty() {
                    return Ok(Ctap2Response::error(Ctap2Status::InvalidLength));
                }
                let Some(mut continuation) = self.assertion_continuations.remove(&channel) else {
                    return Ok(Ctap2Response::error(Ctap2Status::NotAllowed));
                };
                if Instant::now() >= continuation.expires_at {
                    return Ok(Ctap2Response::error(Ctap2Status::NotAllowed));
                }
                let Some(credential_id) = continuation.credentials.pop_front() else {
                    return Ok(Ctap2Response::error(Ctap2Status::NotAllowed));
                };
                let result = execute_next_assertion_with_uv_and_hmac_secret(
                    &continuation.request,
                    &credential_id,
                    self.store,
                    self.key_store,
                    continuation.user_verified,
                    continuation.hmac_secret_shared_secret.as_ref(),
                )
                .map_err(AuthenticatorServiceError::GetAssertion)?;
                if result.status != Ctap2Status::Success {
                    return Ok(Ctap2Response::error(Ctap2Status::NotAllowed));
                }
                continuation.expires_at = Instant::now() + ASSERTION_CONTINUATION_TIMEOUT;
                if !continuation.credentials.is_empty() {
                    self.assertion_continuations.insert(channel, continuation);
                }
                Ok(result)
            }
            Ctap2Command::ClientPin => {
                Ok(self.client_pin.handle(channel, decoded_payload, self.store))
            }
            Ctap2Command::Config => {
                if !self.store.has_protected_storage() {
                    return Ok(Ctap2Response::error(Ctap2Status::InvalidCommand));
                }
                let always_uv = self.always_uv_enabled();
                Ok(self
                    .client_pin
                    .handle_config(channel, decoded_payload, self.store, always_uv))
            }
            Ctap2Command::CredentialManagement => {
                Ok(self.handle_credential_management(channel, decoded_payload))
            }
            Ctap2Command::LargeBlobs => Ok(self.handle_large_blobs(channel, decoded_payload)),
            Ctap2Command::Selection => {
                if !payload.is_empty() {
                    return Ok(Ctap2Response::error(Ctap2Status::InvalidLength));
                }
                let confirmation = VerificationRequest {
                    relying_party_id: "authenticator".into(),
                    relying_party_name: Some("Authenticator selection".into()),
                    action: VerificationAction::SelectAuthenticator,
                };
                match self
                    .verification
                    .request_confirmation(&confirmation, self.config.request_timeout)
                {
                    Ok(VerificationDecision::Approved) => Ok(Ctap2Response {
                        status: Ctap2Status::Success,
                        payload: Vec::new(),
                    }),
                    Ok(_) => Ok(Ctap2Response::error(Ctap2Status::OperationDenied)),
                    Err(error) if error.kind == PlatformErrorKind::Timeout => {
                        Ok(Ctap2Response::error(Ctap2Status::UserActionTimeout))
                    }
                    Err(_) => Ok(Ctap2Response::error(Ctap2Status::Other)),
                }
            }
            Ctap2Command::Reset => {
                if !payload.is_empty() {
                    return Ok(Ctap2Response::error(Ctap2Status::InvalidLength));
                }
                if self.started_at.elapsed() > RESET_POWER_UP_WINDOW {
                    return Ok(Ctap2Response::error(Ctap2Status::NotAllowed));
                }
                let confirmation = VerificationRequest {
                    relying_party_id: "authenticator".into(),
                    relying_party_name: Some("Reset all authenticator credentials".into()),
                    action: VerificationAction::ResetAuthenticator,
                };
                let decision = match self
                    .verification
                    .request_confirmation(&confirmation, self.config.request_timeout)
                {
                    Ok(decision) => decision,
                    Err(error) if error.kind == PlatformErrorKind::Timeout => {
                        return Ok(Ctap2Response::error(Ctap2Status::UserActionTimeout));
                    }
                    Err(_) => return Ok(Ctap2Response::error(Ctap2Status::Other)),
                };
                if decision != VerificationDecision::Approved {
                    return Ok(Ctap2Response::error(Ctap2Status::OperationDenied));
                }
                let _references = match self
                    .store
                    .provider_key_handles()
                    .into_iter()
                    .map(|handle| {
                        let reference = std::str::from_utf8(handle.as_bytes()).map_err(|_| ())?;
                        if reference.is_empty() {
                            return Err(());
                        }
                        Ok(KeyReference::new(reference))
                    })
                    .collect::<Result<Vec<_>, ()>>()
                {
                    Ok(references) => references,
                    Err(()) => return Ok(Ctap2Response::error(Ctap2Status::Other)),
                };
                if self.store.begin_reset().is_err() || self.recover_pending_reset().is_err() {
                    return Ok(Ctap2Response::error(Ctap2Status::Other));
                }
                Ok(Ctap2Response::error(Ctap2Status::Success))
            }
        }
    }

    pub(crate) fn clear_channel(&mut self, channel: u32) {
        self.assertion_continuations.remove(&channel);
        self.credential_management.remove(&channel);
        self.large_blob_writes.remove(&channel);
    }

    fn recover_pending_reset(&mut self) -> Result<(), ()> {
        self.large_blob_writes.clear();
        if self.store.metadata_key_cleanup_pending() {
            self.store.complete_metadata_key_cleanup().map_err(|_| ())?;
            self.assertion_continuations.clear();
            self.credential_management.clear();
            self.client_pin.clear_all();
            return Ok(());
        }
        self.store.begin_reset().map_err(|_| ())?;
        loop {
            let handle = self
                .store
                .pending_reset_key_handles()
                .and_then(|pending| pending.first().cloned());
            let Some(handle) = handle else {
                break;
            };
            let reference = std::str::from_utf8(handle.as_bytes()).map_err(|_| ())?;
            self.key_store
                .delete_key(&KeyReference::new(reference))
                .map_err(|_| ())?;
            self.store.mark_reset_key_deleted(&handle).map_err(|_| ())?;
        }
        self.store.finish_reset().map_err(|_| ())?;
        self.store.complete_metadata_key_cleanup().map_err(|_| ())?;
        self.assertion_continuations.clear();
        self.credential_management.clear();
        self.client_pin.clear_all();
        Ok(())
    }

    fn recover_pending_provider_key(&mut self) -> Result<(), ()> {
        if let Some((id, handle)) = self.store.pending_credential_deletion() {
            let reference = std::str::from_utf8(handle.as_bytes()).map_err(|_| ())?;
            self.key_store
                .delete_key(&crate::KeyReference::new(reference))
                .map_err(|_| ())?;
            return self
                .store
                .finish_credential_deletion(&id, &handle)
                .map_err(|_| ());
        }
        let handle = self
            .store
            .pending_provider_key_handle()
            .cloned()
            .ok_or(())?;
        let reference = std::str::from_utf8(handle.as_bytes()).map_err(|_| ())?;
        self.key_store
            .delete_key(&crate::KeyReference::new(reference))
            .map_err(|_| ())?;
        self.store
            .mark_provider_key_deleted(&handle)
            .map_err(|_| ())
    }

    /// Clears per-channel state after the transport reports cancellation or expiry.
    pub fn cancel_channel(&mut self, channel: u32) {
        self.clear_channel(channel);
        self.credential_management.remove(&channel);
        self.client_pin.clear_channel(channel);
    }

    fn ensure_credential_management_metadata(&mut self) -> bool {
        let records = self.store.discoverable_records();
        for record in records {
            if record.relying_party_id.is_none() {
                return false;
            }
            if record.public_key.is_some() {
                continue;
            }
            let Ok(reference) = std::str::from_utf8(record.key_handle.as_bytes()) else {
                return false;
            };
            let Ok(public_key) = self.key_store.public_key(&KeyReference::new(reference)) else {
                return false;
            };
            if self.store.set_public_key(&record.id, public_key).is_err() {
                return false;
            }
        }
        true
    }

    fn handle_large_blobs(&mut self, channel: u32, value: Option<CborValue>) -> Ctap2Response {
        if !self.store.supports_large_blobs() || self.config.get_info.max_msg_size <= 64 {
            return Ctap2Response::error(Ctap2Status::InvalidCommand);
        }
        let now = Instant::now();
        if self.large_blob_writes.get(&channel).is_some_and(|state| {
            state
                .pin_uv_auth_token_expires_at
                .is_some_and(|expires_at| now >= expires_at)
        }) {
            self.large_blob_writes.remove(&channel);
        }
        let Some(CborValue::Map(fields)) = value else {
            return Ctap2Response::error(Ctap2Status::CborUnexpectedType);
        };
        if fields
            .iter()
            .enumerate()
            .any(|(index, (key, _))| fields[..index].iter().any(|(previous, _)| previous == key))
        {
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        }

        let get = match field(&fields, 1) {
            Some(CborValue::Unsigned(value)) => Some(*value),
            Some(_) => return Ctap2Response::error(Ctap2Status::CborUnexpectedType),
            None => None,
        };
        let set = match field(&fields, 2) {
            Some(CborValue::Bytes(value)) => Some(value.as_slice()),
            Some(_) => return Ctap2Response::error(Ctap2Status::CborUnexpectedType),
            None => None,
        };
        let offset = match field(&fields, 3) {
            Some(CborValue::Unsigned(value)) => *value,
            Some(_) => return Ctap2Response::error(Ctap2Status::CborUnexpectedType),
            None => return Ctap2Response::error(Ctap2Status::InvalidParameter),
        };
        let length = match field(&fields, 4) {
            Some(CborValue::Unsigned(value)) => Some(*value),
            Some(_) => return Ctap2Response::error(Ctap2Status::CborUnexpectedType),
            None => None,
        };
        let pin_auth = match field(&fields, 5) {
            Some(CborValue::Bytes(value)) => Some(value.as_slice()),
            Some(_) => return Ctap2Response::error(Ctap2Status::CborUnexpectedType),
            None => None,
        };
        let pin_protocol_id = match field(&fields, 6) {
            Some(CborValue::Unsigned(value)) => Some(*value),
            Some(_) => return Ctap2Response::error(Ctap2Status::CborUnexpectedType),
            None => None,
        };
        if get.is_some() == set.is_some() {
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        }

        let max_fragment = self
            .config
            .get_info
            .max_msg_size
            .saturating_sub(64)
            .min(usize::MAX as u64) as usize;
        if let Some(requested) = get {
            if length.is_some() || pin_auth.is_some() || pin_protocol_id.is_some() {
                return Ctap2Response::error(Ctap2Status::InvalidParameter);
            }
            if requested > max_fragment as u64 {
                return Ctap2Response::error(Ctap2Status::InvalidLength);
            }
            let Ok(offset) = usize::try_from(offset) else {
                return Ctap2Response::error(Ctap2Status::InvalidParameter);
            };
            let array = self.store.large_blob_array();
            if offset > array.len() {
                return Ctap2Response::error(Ctap2Status::InvalidParameter);
            }
            let end = offset.saturating_add(requested as usize).min(array.len());
            return response_map(vec![(1, CborValue::Bytes(array[offset..end].to_vec()))]);
        }

        let Some(set) = set else {
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        };
        if set.len() > max_fragment {
            return Ctap2Response::error(Ctap2Status::InvalidLength);
        }
        if offset > u64::from(u32::MAX) {
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        }
        let expected_length = if offset == 0 {
            let Some(length) = length else {
                return Ctap2Response::error(Ctap2Status::InvalidParameter);
            };
            if length < 17 {
                return Ctap2Response::error(Ctap2Status::InvalidParameter);
            }
            if length > MAX_SERIALIZED_LARGE_BLOB_ARRAY as u64 && length > 1024 {
                return Ctap2Response::error(Ctap2Status::LargeBlobStorageFull);
            }
            match usize::try_from(length) {
                Ok(length) if length <= MAX_SERIALIZED_LARGE_BLOB_ARRAY => length,
                _ => return Ctap2Response::error(Ctap2Status::LargeBlobStorageFull),
            }
        } else {
            if length.is_some() {
                return Ctap2Response::error(Ctap2Status::InvalidParameter);
            }
            let Some(state) = self.large_blob_writes.get(&channel) else {
                return Ctap2Response::error(Ctap2Status::InvalidSequence);
            };
            if offset != state.bytes.len() as u64 {
                return Ctap2Response::error(Ctap2Status::InvalidSequence);
            }
            state.expected_length
        };
        if offset == 0 && length.is_none() {
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        }

        let pin_configured = self.store.pin_state().verifier().is_some();
        let always_uv = self.always_uv_enabled();
        let auth_required = pin_configured || always_uv;
        let mut pin_uv_auth_token_expires_at = None;
        if auth_required {
            let Some(auth) = pin_auth else {
                return Ctap2Response::error(Ctap2Status::PinUvAuthTokenRequired);
            };
            let Some(protocol_id) = pin_protocol_id else {
                return Ctap2Response::error(Ctap2Status::MissingParameter);
            };
            let Some(protocol) = PinUvAuthProtocol::from_id(protocol_id) else {
                return Ctap2Response::error(Ctap2Status::InvalidParameter);
            };
            let mut auth_message = Vec::with_capacity(70);
            auth_message.extend_from_slice(&[0xff; 32]);
            auth_message.extend_from_slice(&[0x0c, 0x00]);
            auth_message.extend_from_slice(&(offset as u32).to_le_bytes());
            auth_message.extend_from_slice(&Sha256::digest(set));
            let authorization = self.client_pin.authorize_permission(
                channel,
                &auth_message,
                auth,
                protocol,
                PIN_UV_PERMISSION_LARGE_BLOB_WRITE,
            );
            pin_uv_auth_token_expires_at = match authorization {
                Ok(expires_at) => Some(expires_at),
                Err(status) => {
                    if status == Ctap2Status::PinUvAuthTokenRequired {
                        self.large_blob_writes.remove(&channel);
                    }
                    return Ctap2Response::error(
                        if status == Ctap2Status::UnauthorizedPermission {
                            Ctap2Status::PinAuthInvalid
                        } else {
                            status
                        },
                    );
                }
            };
        }

        let offset = offset as usize;
        let current_length = if offset == 0 {
            0
        } else {
            self.large_blob_writes
                .get(&channel)
                .map_or(0, |state| state.bytes.len())
        };
        let Some(next_length) = current_length.checked_add(set.len()) else {
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        };
        if next_length > expected_length {
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        }

        if offset == 0 {
            self.large_blob_writes.insert(
                channel,
                LargeBlobWriteState {
                    expected_length,
                    bytes: Zeroizing::new(Vec::with_capacity(expected_length)),
                    expires_at: Instant::now() + LARGE_BLOB_WRITE_TIMEOUT,
                    pin_uv_auth_token_expires_at,
                },
            );
        }
        let Some(state) = self.large_blob_writes.get_mut(&channel) else {
            return Ctap2Response::error(Ctap2Status::InvalidSequence);
        };
        state.bytes.extend_from_slice(set);
        state.expires_at = Instant::now() + LARGE_BLOB_WRITE_TIMEOUT;
        if state.bytes.len() == state.expected_length {
            let complete = Zeroizing::new(state.bytes.to_vec());
            self.large_blob_writes.remove(&channel);
            let content_length = complete.len() - 16;
            if complete[content_length..] != Sha256::digest(&complete[..content_length])[..16] {
                return Ctap2Response::error(Ctap2Status::IntegrityFailure);
            }
            if self
                .store
                .replace_large_blob_array(complete.as_slice())
                .is_err()
            {
                return Ctap2Response::error(Ctap2Status::Other);
            }
        }
        Ctap2Response {
            status: Ctap2Status::Success,
            payload: Vec::new(),
        }
    }

    fn handle_credential_management(
        &mut self,
        channel: u32,
        value: Option<CborValue>,
    ) -> Ctap2Response {
        let Some(CborValue::Map(fields)) = value else {
            return Ctap2Response::error(Ctap2Status::CborUnexpectedType);
        };
        if fields
            .iter()
            .enumerate()
            .any(|(index, (key, _))| fields[..index].iter().any(|(previous, _)| previous == key))
        {
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        }
        let Some(subcommand) = uint_field(&fields, 1).and_then(|value| u8::try_from(value).ok())
        else {
            return Ctap2Response::error(Ctap2Status::MissingParameter);
        };
        let params = field(&fields, 2);
        let (auth, protocol) = if matches!(subcommand, 3 | 5) {
            (None, None)
        } else {
            let Some(auth) = byte_field(&fields, 4) else {
                return Ctap2Response::error(Ctap2Status::PinUvAuthTokenRequired);
            };
            let Some(protocol) = uint_field(&fields, 3).and_then(PinUvAuthProtocol::from_id) else {
                return Ctap2Response::error(Ctap2Status::InvalidParameter);
            };
            if auth.len() != protocol.auth_parameter_size() {
                return Ctap2Response::error(Ctap2Status::InvalidParameter);
            }
            (Some(auth), Some(protocol))
        };
        let parameter_value = params.cloned().unwrap_or(CborValue::Map(Vec::new()));
        let CborValue::Map(parameter_fields) = &parameter_value else {
            return Ctap2Response::error(Ctap2Status::CborUnexpectedType);
        };
        if parameter_fields
            .iter()
            .enumerate()
            .any(|(index, (key, _))| {
                parameter_fields[..index]
                    .iter()
                    .any(|(previous, _)| previous == key)
            })
        {
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        }
        let mut auth_message = vec![subcommand];
        if params.is_some() {
            match encode_cbor(&parameter_value) {
                Ok(encoded) => auth_message.extend_from_slice(&encoded),
                Err(_) => return Ctap2Response::error(Ctap2Status::Other),
            }
        }
        match subcommand {
            1 => {
                if params.is_some() {
                    return Ctap2Response::error(Ctap2Status::InvalidParameter);
                }
                let (Some(auth), Some(protocol)) = (auth, protocol) else {
                    return Ctap2Response::error(Ctap2Status::PinUvAuthTokenRequired);
                };
                if let Err(status) =
                    self.client_pin
                        .authorize(channel, &auth_message, auth, protocol, 0x04, None)
                {
                    return Ctap2Response::error(credential_management_auth_status(status));
                }
                if !self.can_start_credential_management(channel) {
                    return Ctap2Response::error(Ctap2Status::ChannelBusy);
                }
                let credentials = self.store.discoverable_records();
                let count = credentials.len() as u64;
                response_map(vec![
                    (1, CborValue::Unsigned(count)),
                    (
                        2,
                        CborValue::Unsigned(self.store.remaining_capacity() as u64),
                    ),
                ])
            }
            2 => {
                if params.is_some() {
                    return Ctap2Response::error(Ctap2Status::InvalidParameter);
                }
                let (Some(auth), Some(protocol)) = (auth, protocol) else {
                    return Ctap2Response::error(Ctap2Status::PinUvAuthTokenRequired);
                };
                let pin_uv_auth_token_expires_at = match self.client_pin.authorize(
                    channel,
                    &auth_message,
                    auth,
                    protocol,
                    0x04,
                    None,
                ) {
                    Ok(()) => self.client_pin.token_expiration(channel),
                    Err(status) => {
                        return Ctap2Response::error(credential_management_auth_status(status));
                    }
                };
                if !self.can_start_credential_management(channel) {
                    return Ctap2Response::error(Ctap2Status::ChannelBusy);
                }
                self.credential_management.remove(&channel);
                let mut groups = BTreeMap::<String, ([u8; 32], u64)>::new();
                for record in self.store.discoverable_records() {
                    let Some(rp_id) = record.relying_party_id else {
                        return Ctap2Response::error(Ctap2Status::Other);
                    };
                    if <[u8; 32]>::from(Sha256::digest(rp_id.as_bytes())) != record.rp_id_hash {
                        return Ctap2Response::error(Ctap2Status::Other);
                    }
                    let entry = groups.entry(rp_id).or_insert((record.rp_id_hash, 0));
                    if entry.0 != record.rp_id_hash {
                        return Ctap2Response::error(Ctap2Status::Other);
                    }
                    entry.1 = entry.1.saturating_add(1);
                }
                if groups.is_empty() {
                    return Ctap2Response::error(Ctap2Status::NoCredentials);
                }
                let entries = groups
                    .into_iter()
                    .map(|(id, (hash, count))| (id, hash, count))
                    .collect::<Vec<_>>();
                let total = entries.len() as u64;
                let first = entries[0].clone();
                self.credential_management.insert(
                    channel,
                    CredentialManagementContinuation {
                        expires_at: Instant::now() + CREDENTIAL_MANAGEMENT_TIMEOUT,
                        pin_uv_auth_token_expires_at,
                        position: 1,
                        entries: CredentialManagementEntries::RelyingParties(entries),
                    },
                );
                rp_response(&first, total)
            }
            3 => {
                if params.is_some() {
                    return Ctap2Response::error(Ctap2Status::InvalidParameter);
                }
                self.next_credential_management_rp(channel)
            }
            4 => {
                let (Some(auth), Some(protocol)) = (auth, protocol) else {
                    return Ctap2Response::error(Ctap2Status::PinUvAuthTokenRequired);
                };
                let Some(CborValue::Bytes(rp_hash)) = field(parameter_fields, 1) else {
                    return Ctap2Response::error(Ctap2Status::MissingParameter);
                };
                let Ok(rp_hash): Result<[u8; 32], _> = rp_hash.as_slice().try_into() else {
                    return Ctap2Response::error(Ctap2Status::InvalidParameter);
                };
                let pin_uv_auth_token_expires_at = match self.client_pin.authorize(
                    channel,
                    &auth_message,
                    auth,
                    protocol,
                    0x04,
                    None,
                ) {
                    Ok(()) => self.client_pin.token_expiration(channel),
                    Err(status) => {
                        return Ctap2Response::error(credential_management_auth_status(status));
                    }
                };
                if !self.can_start_credential_management(channel) {
                    return Ctap2Response::error(Ctap2Status::ChannelBusy);
                }
                self.credential_management.remove(&channel);
                let records = self.store.discoverable_records();
                let matching = records
                    .iter()
                    .filter(|record| record.rp_id_hash == rp_hash)
                    .cloned()
                    .collect::<Vec<_>>();
                let Some(rp_id) = matching
                    .first()
                    .and_then(|record| record.relying_party_id.clone())
                else {
                    return Ctap2Response::error(Ctap2Status::NoCredentials);
                };
                if matching.iter().any(|record| {
                    record.relying_party_id.as_deref() != Some(rp_id.as_str())
                        || record.rp_id_hash != rp_hash
                }) {
                    return Ctap2Response::error(Ctap2Status::Other);
                }
                if matching.is_empty() {
                    return Ctap2Response::error(Ctap2Status::NoCredentials);
                }
                let total = matching.len() as u64;
                let first = matching[0].clone();
                let response = self.credential_response(&first, total);
                if response.status == Ctap2Status::Success {
                    self.credential_management.insert(
                        channel,
                        CredentialManagementContinuation {
                            expires_at: Instant::now() + CREDENTIAL_MANAGEMENT_TIMEOUT,
                            pin_uv_auth_token_expires_at,
                            position: 1,
                            entries: CredentialManagementEntries::Credentials { records: matching },
                        },
                    );
                }
                response
            }
            5 => {
                if params.is_some() {
                    return Ctap2Response::error(Ctap2Status::InvalidParameter);
                }
                self.next_credential_management_credential(channel)
            }
            6 | 7 => {
                let (Some(auth), Some(protocol)) = (auth, protocol) else {
                    return Ctap2Response::error(Ctap2Status::PinUvAuthTokenRequired);
                };
                let descriptor = match field(parameter_fields, 2) {
                    None => return Ctap2Response::error(Ctap2Status::MissingParameter),
                    Some(CborValue::Map(descriptor)) => descriptor,
                    Some(_) => return Ctap2Response::error(Ctap2Status::CborUnexpectedType),
                };
                match text_map_field(descriptor, "type") {
                    None => return Ctap2Response::error(Ctap2Status::CborUnexpectedType),
                    Some(CborValue::Text(value)) if value == "public-key" => {}
                    Some(CborValue::Text(_)) => {
                        return Ctap2Response::error(Ctap2Status::InvalidParameter);
                    }
                    Some(_) => return Ctap2Response::error(Ctap2Status::CborUnexpectedType),
                }
                if descriptor.iter().enumerate().any(|(index, (key, _))| {
                    descriptor[..index]
                        .iter()
                        .any(|(previous, _)| previous == key)
                }) {
                    return Ctap2Response::error(Ctap2Status::InvalidParameter);
                }
                if let Some(transports) = text_map_field(descriptor, "transports") {
                    if !matches!(transports, CborValue::Array(values) if values.iter().all(|value| matches!(value, CborValue::Text(_))))
                    {
                        return Ctap2Response::error(Ctap2Status::CborUnexpectedType);
                    }
                }
                let id_bytes = match text_map_field(descriptor, "id") {
                    None => return Ctap2Response::error(Ctap2Status::CborUnexpectedType),
                    Some(CborValue::Bytes(id_bytes)) => id_bytes,
                    Some(_) => return Ctap2Response::error(Ctap2Status::CborUnexpectedType),
                };
                let Ok(id) = CredentialId::new(id_bytes.to_vec()) else {
                    return Ctap2Response::error(Ctap2Status::InvalidParameter);
                };
                if let Err(status) = self.client_pin.authorize_permission(
                    channel,
                    &auth_message,
                    auth,
                    protocol,
                    0x04,
                ) {
                    return Ctap2Response::error(credential_management_auth_status(status));
                }
                let Some(record) = self
                    .store
                    .discoverable_records()
                    .into_iter()
                    .find(|record| record.id == id)
                else {
                    return Ctap2Response::error(Ctap2Status::NoCredentials);
                };
                let Some(rp_id) = record.relying_party_id.as_deref() else {
                    return Ctap2Response::error(Ctap2Status::Other);
                };
                if let Err(status) = self.client_pin.authorize(
                    channel,
                    &auth_message,
                    auth,
                    protocol,
                    0x04,
                    Some(rp_id),
                ) {
                    return Ctap2Response::error(credential_management_auth_status(status));
                }
                if subcommand == 6 {
                    let Ok(reference) = std::str::from_utf8(record.key_handle.as_bytes()) else {
                        return Ctap2Response::error(Ctap2Status::Other);
                    };
                    let handle = match self.store.begin_credential_deletion(&id) {
                        Ok(handle) => handle,
                        Err(_) => return Ctap2Response::error(Ctap2Status::Other),
                    };
                    if self
                        .key_store
                        .delete_key(&KeyReference::new(reference))
                        .is_err()
                    {
                        return Ctap2Response::error(Ctap2Status::Other);
                    }
                    match self.store.finish_credential_deletion(&id, &handle) {
                        Ok(()) => Ctap2Response::error(Ctap2Status::Success),
                        Err(_) => Ctap2Response::error(Ctap2Status::Other),
                    }
                } else {
                    let user = match field(parameter_fields, 3) {
                        None => return Ctap2Response::error(Ctap2Status::MissingParameter),
                        Some(CborValue::Map(user)) => user,
                        Some(_) => return Ctap2Response::error(Ctap2Status::CborUnexpectedType),
                    };
                    if user.iter().enumerate().any(|(index, (key, _))| {
                        user[..index].iter().any(|(previous, _)| previous == key)
                    }) {
                        return Ctap2Response::error(Ctap2Status::InvalidParameter);
                    }
                    let user_id = match text_map_field(user, "id") {
                        None => return Ctap2Response::error(Ctap2Status::CborUnexpectedType),
                        Some(CborValue::Bytes(user_id)) => user_id,
                        Some(_) => return Ctap2Response::error(Ctap2Status::CborUnexpectedType),
                    };
                    let name = optional_text_field(user, "name");
                    let display_name = optional_text_field(user, "displayName");
                    let (name, display_name) = match (name, display_name) {
                        (Ok(name), Ok(display_name)) => (name, display_name),
                        (Err(status), _) | (_, Err(status)) => return Ctap2Response::error(status),
                    };
                    let name = name.filter(|value| !value.is_empty());
                    let display_name = display_name.filter(|value| !value.is_empty());
                    match self
                        .store
                        .update_user_labels(&id, user_id, name, display_name)
                    {
                        Ok(()) => Ctap2Response::error(Ctap2Status::Success),
                        Err(CredentialError::StorageFull) => {
                            Ctap2Response::error(Ctap2Status::KeyStoreFull)
                        }
                        Err(CredentialError::NotFound | CredentialError::UserLabelTooLong) => {
                            Ctap2Response::error(Ctap2Status::InvalidParameter)
                        }
                        Err(_) => Ctap2Response::error(Ctap2Status::Other),
                    }
                }
            }
            _ => Ctap2Response::error(Ctap2Status::InvalidParameter),
        }
    }

    fn next_credential_management_rp(&mut self, channel: u32) -> Ctap2Response {
        let Some(state) = self.credential_management.get_mut(&channel) else {
            return Ctap2Response::error(Ctap2Status::NoCredentials);
        };
        if Instant::now() >= state.expires_at {
            self.credential_management.remove(&channel);
            return Ctap2Response::error(Ctap2Status::NoCredentials);
        }
        let CredentialManagementEntries::RelyingParties(entries) = &state.entries else {
            return Ctap2Response::error(Ctap2Status::NotAllowed);
        };
        let Some(entry) = entries.get(state.position).cloned() else {
            self.credential_management.remove(&channel);
            return Ctap2Response::error(Ctap2Status::NoCredentials);
        };
        let total = entries.len() as u64;
        state.position += 1;
        state.expires_at = Instant::now() + CREDENTIAL_MANAGEMENT_TIMEOUT;
        rp_response(&entry, total)
    }

    fn can_start_credential_management(&mut self, channel: u32) -> bool {
        let now = Instant::now();
        self.credential_management
            .retain(|_, state| now < state.expires_at);
        self.credential_management.contains_key(&channel)
            || self.credential_management.len() < MAX_CREDENTIAL_MANAGEMENT_CHANNELS
    }

    fn next_credential_management_credential(&mut self, channel: u32) -> Ctap2Response {
        let (record, total) = {
            let Some(state) = self.credential_management.get(&channel) else {
                return Ctap2Response::error(Ctap2Status::NoCredentials);
            };
            if Instant::now() >= state.expires_at {
                self.credential_management.remove(&channel);
                return Ctap2Response::error(Ctap2Status::NoCredentials);
            }
            let CredentialManagementEntries::Credentials { records, .. } = &state.entries else {
                return Ctap2Response::error(Ctap2Status::NotAllowed);
            };
            let Some(record) = records.get(state.position).cloned() else {
                self.credential_management.remove(&channel);
                return Ctap2Response::error(Ctap2Status::NoCredentials);
            };
            (record, records.len() as u64)
        };
        let response = self.credential_response(&record, total);
        if response.status == Ctap2Status::Success {
            if let Some(state) = self.credential_management.get_mut(&channel) {
                state.position += 1;
                state.expires_at = Instant::now() + CREDENTIAL_MANAGEMENT_TIMEOUT;
            }
        }
        response
    }

    fn credential_response(
        &mut self,
        record: &ghost_fido_core::CredentialRecord,
        total: u64,
    ) -> Ctap2Response {
        let public_key = if let Some(key) = &record.public_key {
            key.clone()
        } else {
            let Ok(reference) = std::str::from_utf8(record.key_handle.as_bytes()) else {
                return Ctap2Response::error(Ctap2Status::Other);
            };
            let Ok(key) = self.key_store.public_key(&KeyReference::new(reference)) else {
                return Ctap2Response::error(Ctap2Status::Other);
            };
            if self.store.set_public_key(&record.id, key.clone()).is_err() {
                return Ctap2Response::error(Ctap2Status::Other);
            }
            key
        };
        let user = user_entity(record);
        response_map(vec![
            (6, user),
            (
                7,
                CborValue::Map(vec![
                    (
                        CborValue::Text("type".into()),
                        CborValue::Text("public-key".into()),
                    ),
                    (
                        CborValue::Text("id".into()),
                        CborValue::Bytes(record.id.as_bytes().to_vec()),
                    ),
                ]),
            ),
            (
                8,
                CborValue::Map(vec![
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
                ]),
            ),
            (9, CborValue::Unsigned(total)),
            (
                10,
                CborValue::Unsigned(u64::from(record.cred_protect as u8)),
            ),
        ])
    }

    fn verify_pin_authorization(
        &mut self,
        channel: u32,
        client_data_hash: &[u8; 32],
        auth: Option<(Vec<u8>, PinUvAuthProtocol)>,
        uv_required: bool,
        always_uv: bool,
        permission: u8,
        relying_party_id: &str,
    ) -> Result<(bool, Option<Instant>), Ctap2Status> {
        match auth {
            Some((auth, protocol)) => {
                self.client_pin.authorize(
                    channel,
                    client_data_hash,
                    &auth,
                    protocol,
                    permission,
                    Some(relying_party_id),
                )?;
                Ok((true, self.client_pin.token_expiration(channel)))
            }
            None if uv_required => Err(Ctap2Status::InvalidOption),
            None if always_uv => Err(if self.store.has_protected_storage() {
                Ctap2Status::PinUvAuthTokenRequired
            } else {
                Ctap2Status::OperationDenied
            }),
            None => Ok((false, None)),
        }
    }
}

fn parse_pin_auth(
    value: Option<&CborValue>,
    auth_key: u64,
    protocol_key: u64,
) -> Result<Option<(Vec<u8>, PinUvAuthProtocol)>, Ctap2Status> {
    let Some(CborValue::Map(fields)) = value else {
        return Ok(None);
    };
    if has_duplicate_field(fields, auth_key) || has_duplicate_field(fields, protocol_key) {
        return Err(Ctap2Status::InvalidParameter);
    }
    match (field(fields, auth_key), field(fields, protocol_key)) {
        (None, None) => Ok(None),
        (Some(CborValue::Bytes(auth)), protocol_value) => {
            let protocol = match protocol_value {
                None => PinUvAuthProtocol::One,
                Some(CborValue::Unsigned(id)) => {
                    PinUvAuthProtocol::from_id(*id).ok_or(Ctap2Status::InvalidParameter)?
                }
                Some(_) => return Err(Ctap2Status::InvalidParameter),
            };
            if auth.len() != protocol.auth_parameter_size() {
                return Err(Ctap2Status::InvalidParameter);
            }
            Ok(Some((auth.clone(), protocol)))
        }
        (Some(_), Some(_)) => Err(Ctap2Status::InvalidParameter),
        _ => Err(Ctap2Status::MissingParameter),
    }
}

fn has_duplicate_field(fields: &[(CborValue, CborValue)], key: u64) -> bool {
    fields
        .iter()
        .filter(|(candidate, _)| *candidate == CborValue::Unsigned(key))
        .count()
        > 1
}

fn encrypted_size(plaintext_size: usize, protocol: PinUvAuthProtocol) -> usize {
    plaintext_size + usize::from(protocol == PinUvAuthProtocol::Two) * 16
}
