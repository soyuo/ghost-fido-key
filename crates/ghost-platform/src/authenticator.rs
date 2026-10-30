//! CTAP2 command routing across the platform-independent core and providers.

use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use ghost_fido_core::{
    CborValue, CredentialId, CredentialStore, Ctap2Command, Ctap2Request, Ctap2Response,
    Ctap2Status, GetAssertionRequest, GetInfoError, GetInfoHandler, GetInfoProfile,
    MakeCredentialRequest, PIN_ENCRYPTED_SIZE, PIN_HASH_SIZE, PIN_UV_AUTH_PARAMETER_SIZE,
    PIN_UV_AUTH_PROTOCOL, PinKeyAgreement, client_pin_decrypt, client_pin_decrypt_pin,
    client_pin_encrypt, client_pin_hash, client_pin_verify_authentication, decode_cbor,
    encode_cbor,
};

const PIN_PROTOCOL_TIMEOUT: Duration = Duration::from_secs(30);

use crate::{
    GetAssertionExecutionError, KeyCreationPolicy, KeyReference, KeyStore,
    MakeCredentialExecutionError, PlatformErrorKind, SoftwareKeyConsent, UserVerification,
    VerificationAction, VerificationDecision, VerificationRequest,
    execute_get_assertion_with_uv_and_hmac_secret, execute_next_assertion_with_uv_and_hmac_secret,
};

const ASSERTION_CONTINUATION_TIMEOUT: Duration = Duration::from_secs(30);
const CREDENTIAL_MANAGEMENT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CREDENTIAL_MANAGEMENT_CHANNELS: usize = 8;
const RESET_POWER_UP_WINDOW: Duration = Duration::from_secs(10);
const LEGACY_CHANNEL: u32 = u32::MAX;

struct AssertionContinuation {
    request: GetAssertionRequest,
    credentials: VecDeque<CredentialId>,
    expires_at: Instant,
    user_verified: bool,
    hmac_secret_shared_secret: Option<[u8; 32]>,
}

impl Drop for AssertionContinuation {
    fn drop(&mut self) {
        if let Some(secret) = &mut self.hmac_secret_shared_secret {
            secret.zeroize();
        }
    }
}

struct CredentialManagementContinuation {
    expires_at: Instant,
    position: usize,
    entries: CredentialManagementEntries,
}

enum CredentialManagementEntries {
    RelyingParties(Vec<(String, [u8; 32], u64)>),
    Credentials {
        relying_party_id: String,
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
    client_pin: ClientPinHandler,
    started_at: Instant,
}

#[derive(Default)]
struct ClientPinHandler {
    agreements: BTreeMap<u32, PinAgreementEntry>,
    tokens: BTreeMap<u32, PinTokenEntry>,
}

struct PinAgreementEntry {
    key: PinKeyAgreement,
    expires_at: Instant,
}

struct PinTokenEntry {
    value: [u8; 32],
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
        permission: u8,
        relying_party_id: Option<&str>,
    ) -> Result<(), Ctap2Status> {
        let relying_party_hash =
            relying_party_id.map(|rp_id| Sha256::digest(rp_id.as_bytes()).into());
        self.authorize_rp_hash(channel, message, auth, permission, relying_party_hash)
    }

    fn authorize_rp_hash(
        &mut self,
        channel: u32,
        message: &[u8],
        auth: &[u8],
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
        if !client_pin_verify_authentication(&token.value, message, auth) {
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
        permission: u8,
    ) -> Result<(), Ctap2Status> {
        self.expire();
        let token = self
            .tokens
            .get(&channel)
            .ok_or(Ctap2Status::PinUvAuthTokenRequired)?;
        if Instant::now() >= token.expires_at {
            self.tokens.remove(&channel);
            return Err(Ctap2Status::PinUvAuthTokenRequired);
        }
        if !client_pin_verify_authentication(&token.value, message, auth) {
            return Err(Ctap2Status::PinAuthInvalid);
        }
        if token.permissions & permission == 0 {
            return Err(Ctap2Status::UnauthorizedPermission);
        }
        Ok(())
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
        let Some(subcommand) = uint_field(&fields, 2).and_then(|number| u8::try_from(number).ok())
        else {
            return Ctap2Response::error(Ctap2Status::MissingParameter);
        };
        let protocol = uint_field(&fields, 1);
        if protocol.is_some_and(|value| value != u64::from(PIN_UV_AUTH_PROTOCOL))
            || (subcommand > 2 && protocol.is_none())
        {
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        }
        if !store.has_protected_storage() {
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        }

        match subcommand {
            1 => response_map(vec![(
                3,
                CborValue::Unsigned(u64::from(store.pin_state().retries())),
            )]),
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
                        expires_at: Instant::now() + PIN_PROTOCOL_TIMEOUT,
                    },
                );
                response_map(vec![(1, public_key)])
            }
            3 => self.set_pin(channel, &fields, store),
            4 => self.change_pin(channel, &fields, store),
            5 => self.get_pin_token(channel, &fields, store),
            9 => self.get_pin_token_with_permissions(channel, &fields, store),
            _ => Ctap2Response::error(Ctap2Status::InvalidParameter),
        }
    }

    fn shared_secret(
        &mut self,
        channel: u32,
        fields: &[(CborValue, CborValue)],
    ) -> Result<Zeroizing<[u8; 32]>, Ctap2Status> {
        let peer = field(fields, 3).ok_or(Ctap2Status::MissingParameter)?;
        let agreement = self
            .agreements
            .remove(&channel)
            .ok_or(Ctap2Status::PinAuthInvalid)?;
        agreement
            .key
            .derive_shared_secret(peer)
            .map_err(|_| Ctap2Status::InvalidParameter)
    }

    fn hmac_secret_shared_secret(
        &mut self,
        channel: u32,
        peer: &CborValue,
    ) -> Result<Zeroizing<[u8; 32]>, Ctap2Status> {
        let agreement = self
            .agreements
            .remove(&channel)
            .ok_or(Ctap2Status::PinAuthInvalid)?;
        agreement
            .key
            .derive_shared_secret(peer)
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
        if encrypted.len() != PIN_ENCRYPTED_SIZE
            || auth.len() != PIN_UV_AUTH_PARAMETER_SIZE
            || !client_pin_verify_authentication(&secret, encrypted, auth)
        {
            secret.zeroize();
            return Ctap2Response::error(Ctap2Status::PinAuthInvalid);
        }
        let mut encrypted_pin = encrypted.to_vec();
        let pin = client_pin_decrypt_pin(&secret, &mut encrypted_pin);
        secret.zeroize();
        let Ok(pin) = pin else {
            return Ctap2Response::error(Ctap2Status::PinPolicyViolation);
        };
        let verifier = client_pin_hash(&pin);
        match store.set_pin_verifier(Some(*verifier)) {
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
        if new_encrypted.len() != PIN_ENCRYPTED_SIZE || hash_encrypted.len() != PIN_HASH_SIZE {
            secret.zeroize();
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        }
        let mut authenticated = new_encrypted.to_vec();
        authenticated.extend_from_slice(hash_encrypted);
        if !client_pin_verify_authentication(&secret, &authenticated, auth) {
            secret.zeroize();
            return Ctap2Response::error(Ctap2Status::PinAuthInvalid);
        }
        let mut encrypted_hash = Zeroizing::new(hash_encrypted.to_vec());
        if client_pin_decrypt(&secret, &mut encrypted_hash).is_err() {
            secret.zeroize();
            return Ctap2Response::error(Ctap2Status::PinAuthInvalid);
        }
        if encrypted_hash
            .as_slice()
            .ct_eq(verifier.as_slice())
            .unwrap_u8()
            != 1
        {
            secret.zeroize();
            let retries = store.pin_state().retries().saturating_sub(1);
            if store.set_pin_retries(retries).is_err() {
                return Ctap2Response::error(Ctap2Status::Other);
            }
            return Ctap2Response::error(if retries == 0 {
                Ctap2Status::PinBlocked
            } else {
                Ctap2Status::PinInvalid
            });
        }
        let mut encrypted_pin = new_encrypted.to_vec();
        let decrypted = client_pin_decrypt_pin(&secret, &mut encrypted_pin);
        secret.zeroize();
        let Ok(pin) = decrypted else {
            return Ctap2Response::error(Ctap2Status::PinPolicyViolation);
        };
        let new_verifier = client_pin_hash(&pin);
        match store.set_pin_verifier(Some(*new_verifier)) {
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
        let Some(permissions) = uint_field(fields, 9).and_then(|value| u8::try_from(value).ok())
        else {
            return Ctap2Response::error(Ctap2Status::MissingParameter);
        };
        if permissions == 0 || permissions & !0x07 != 0 {
            return Ctap2Response::error(Ctap2Status::UnauthorizedPermission);
        }
        let relying_party_id = match field(fields, 10) {
            None => None,
            Some(CborValue::Text(value)) if !value.is_empty() => Some(value.clone()),
            Some(_) => return Ctap2Response::error(Ctap2Status::InvalidParameter),
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
        if encrypted.len() != PIN_HASH_SIZE
            || auth.len() != PIN_UV_AUTH_PARAMETER_SIZE
            || !client_pin_verify_authentication(&secret, encrypted, auth)
        {
            secret.zeroize();
            return Ctap2Response::error(Ctap2Status::PinAuthInvalid);
        }
        let mut decrypted_hash = Zeroizing::new(encrypted.to_vec());
        if client_pin_decrypt(&secret, &mut decrypted_hash).is_err() {
            secret.zeroize();
            return Ctap2Response::error(Ctap2Status::PinAuthInvalid);
        }
        if decrypted_hash
            .as_slice()
            .ct_eq(verifier.as_slice())
            .unwrap_u8()
            != 1
        {
            secret.zeroize();
            let retries = store.pin_state().retries().saturating_sub(1);
            if store.set_pin_retries(retries).is_err() {
                return Ctap2Response::error(Ctap2Status::Other);
            }
            return Ctap2Response::error(if retries == 0 {
                Ctap2Status::PinBlocked
            } else {
                Ctap2Status::PinInvalid
            });
        }
        if store.set_pin_retries(8).is_err() {
            secret.zeroize();
            return Ctap2Response::error(Ctap2Status::Other);
        }
        let mut token = Zeroizing::new([0_u8; 32]);
        if getrandom::fill(&mut token[..]).is_err() {
            secret.zeroize();
            return Ctap2Response::error(Ctap2Status::Other);
        }
        let mut encrypted_token = Zeroizing::new(token.to_vec());
        if client_pin_encrypt(&secret, &mut encrypted_token).is_err() {
            secret.zeroize();
            return Ctap2Response::error(Ctap2Status::Other);
        }
        secret.zeroize();
        // Keep a token copy only in the channel owner, which zeroizes it on drop.
        self.tokens.insert(
            channel,
            PinTokenEntry {
                value: *token,
                expires_at: Instant::now() + PIN_PROTOCOL_TIMEOUT,
                permissions,
                relying_party_hash: relying_party_id
                    .map(|rp_id| Sha256::digest(rp_id.as_bytes()).into()),
            },
        );
        response_map(vec![(
            2,
            CborValue::Bytes(core::mem::take(&mut *encrypted_token)),
        )])
    }
}

fn field(fields: &[(CborValue, CborValue)], key: u64) -> Option<&CborValue> {
    fields
        .iter()
        .find(|(candidate, _)| *candidate == CborValue::Unsigned(key))
        .map(|(_, value)| value)
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

fn optional_text_field(fields: &[(CborValue, CborValue)], key: &str) -> Result<Option<String>, ()> {
    match text_map_field(fields, key) {
        None => Ok(None),
        Some(CborValue::Text(value)) if value.len() <= 256 => Ok(Some(value.clone())),
        _ => Err(()),
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

    /// Returns whether reset cleanup is pending in the credential store.
    #[must_use]
    pub fn reset_is_pending(&self) -> bool {
        self.store.reset_is_pending()
    }

    /// Returns whether provider-key cleanup is pending in the credential store.
    #[must_use]
    pub fn provider_key_cleanup_is_pending(&self) -> bool {
        self.store.pending_provider_key_handle().is_some()
    }

    /// Handles one CTAP2 request and scopes any GetNextAssertion state to its CTAPHID channel.
    pub fn handle_on_channel(
        &mut self,
        channel: u32,
        request: Ctap2Request,
    ) -> Result<Ctap2Response, AuthenticatorServiceError> {
        let (command, payload, decoded_payload) = request.into_parts();
        let resumed_provider_cleanup = self.store.pending_provider_key_handle().is_some();
        if resumed_provider_cleanup && self.recover_pending_provider_key().is_err() {
            return Ok(Ctap2Response::error(Ctap2Status::Other));
        }
        let resumed_reset = self.store.reset_is_pending();
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
        match command {
            Ctap2Command::GetInfo => {
                if !payload.is_empty() {
                    return Ok(Ctap2Response::error(Ctap2Status::InvalidLength));
                }
                let mut profile = self.config.get_info.clone();
                let pin_is_set = self.store.pin_state().verifier().is_some();
                let credential_management_ready =
                    pin_is_set && self.ensure_credential_management_metadata();
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
                profile
                    .extensions
                    .retain(|extension| extension != "hmac-secret" && extension != "credProtect");
                if self.store.has_protected_storage() {
                    profile.extensions.push("hmac-secret".into());
                    profile.extensions.push("credProtect".into());
                }
                profile.pin_uv_auth_protocols = if self.store.has_protected_storage() {
                    vec![u64::from(PIN_UV_AUTH_PROTOCOL)]
                } else {
                    Vec::new()
                };
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
                let user_verified = match self.verify_pin_authorization(
                    channel,
                    &typed.client_data_hash,
                    pin_auth,
                    typed.options.user_verification == Some(true),
                    0x01,
                    &typed.rp.id,
                ) {
                    Ok(value) => value,
                    Err(status) => return Ok(Ctap2Response::error(status)),
                };
                crate::register_make_credential_with_uv(
                    &typed,
                    self.store,
                    self.key_store,
                    self.verification,
                    self.config.key_creation_policy,
                    self.config.software_key_consent,
                    self.config.aaguid,
                    self.config.request_timeout,
                    user_verified,
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
                let mut hmac_secret_shared_secret = if let Some(input) = typed.hmac_secret.as_ref()
                {
                    match self
                        .client_pin
                        .hmac_secret_shared_secret(channel, &input.key_agreement)
                    {
                        Ok(secret) => Some(secret),
                        Err(status) => return Ok(Ctap2Response::error(status)),
                    }
                } else {
                    None
                };
                let user_verified = match self.verify_pin_authorization(
                    channel,
                    &typed.client_data_hash,
                    pin_auth,
                    typed.options.user_verification == Some(true),
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
                let execution = execute_get_assertion_with_uv_and_hmac_secret(
                    &typed,
                    self.store,
                    self.key_store,
                    self.verification,
                    self.config.request_timeout,
                    user_verified,
                    hmac_secret_shared_secret.as_deref(),
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
                            hmac_secret_shared_secret: hmac_secret_shared_secret
                                .as_ref()
                                .map(|secret| **secret),
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
                if !continuation.credentials.is_empty() {
                    self.assertion_continuations.insert(channel, continuation);
                }
                Ok(result)
            }
            Ctap2Command::ClientPin => {
                Ok(self.client_pin.handle(channel, decoded_payload, self.store))
            }
            Ctap2Command::CredentialManagement => {
                Ok(self.handle_credential_management(channel, decoded_payload))
            }
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
            _ => Ok(Ctap2Response::error(Ctap2Status::InvalidCommand)),
        }
    }

    pub(crate) fn clear_channel(&mut self, channel: u32) {
        self.assertion_continuations.remove(&channel);
        self.credential_management.remove(&channel);
    }

    fn recover_pending_reset(&mut self) -> Result<(), ()> {
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
            || fields
                .iter()
                .any(|(key, _)| !matches!(key, CborValue::Unsigned(1..=4)))
        {
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        }
        let Some(subcommand) = uint_field(&fields, 1).and_then(|value| u8::try_from(value).ok())
        else {
            return Ctap2Response::error(Ctap2Status::MissingParameter);
        };
        let params = field(&fields, 2);
        let protocol = uint_field(&fields, 3);
        let Some(auth) = byte_field(&fields, 4) else {
            return Ctap2Response::error(Ctap2Status::PinUvAuthTokenRequired);
        };
        if protocol != Some(u64::from(PIN_UV_AUTH_PROTOCOL))
            || auth.len() != PIN_UV_AUTH_PARAMETER_SIZE
        {
            return Ctap2Response::error(Ctap2Status::InvalidParameter);
        }
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
        let auth: &[u8; PIN_UV_AUTH_PARAMETER_SIZE] = match auth.try_into() {
            Ok(auth) => auth,
            Err(_) => return Ctap2Response::error(Ctap2Status::InvalidParameter),
        };

        match subcommand {
            1 => {
                if params.is_some() {
                    return Ctap2Response::error(Ctap2Status::InvalidParameter);
                }
                if let Err(status) =
                    self.client_pin
                        .authorize(channel, &auth_message, auth, 0x04, None)
                {
                    return Ctap2Response::error(status);
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
                if let Err(status) =
                    self.client_pin
                        .authorize(channel, &auth_message, auth, 0x04, None)
                {
                    return Ctap2Response::error(status);
                }
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
                if let Err(status) =
                    self.client_pin
                        .authorize(channel, &auth_message, auth, 0x04, None)
                {
                    return Ctap2Response::error(status);
                }
                self.next_credential_management_rp(channel)
            }
            4 => {
                if parameter_fields.len() != 1 || field(parameter_fields, 2).is_some() {
                    return Ctap2Response::error(Ctap2Status::InvalidParameter);
                }
                let Some(CborValue::Bytes(rp_hash)) = field(parameter_fields, 1) else {
                    return Ctap2Response::error(Ctap2Status::MissingParameter);
                };
                let Ok(rp_hash): Result<[u8; 32], _> = rp_hash.as_slice().try_into() else {
                    return Ctap2Response::error(Ctap2Status::InvalidParameter);
                };
                if let Err(status) = self.client_pin.authorize_rp_hash(
                    channel,
                    &auth_message,
                    auth,
                    0x04,
                    Some(rp_hash),
                ) {
                    return Ctap2Response::error(status);
                }
                if !self.can_start_credential_management(channel) {
                    return Ctap2Response::error(Ctap2Status::ChannelBusy);
                }
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
                self.credential_management.insert(
                    channel,
                    CredentialManagementContinuation {
                        expires_at: Instant::now() + CREDENTIAL_MANAGEMENT_TIMEOUT,
                        position: 1,
                        entries: CredentialManagementEntries::Credentials {
                            relying_party_id: rp_id,
                            records: matching,
                        },
                    },
                );
                self.credential_response(&first, total)
            }
            5 => {
                let rp_id = match self.credential_management.get(&channel) {
                    Some(CredentialManagementContinuation {
                        entries:
                            CredentialManagementEntries::Credentials {
                                relying_party_id, ..
                            },
                        expires_at,
                        ..
                    }) if Instant::now() < *expires_at => relying_party_id.clone(),
                    _ => return Ctap2Response::error(Ctap2Status::NoCredentials),
                };
                if params.is_some() {
                    return Ctap2Response::error(Ctap2Status::InvalidParameter);
                }
                if let Err(status) =
                    self.client_pin
                        .authorize(channel, &auth_message, auth, 0x04, Some(&rp_id))
                {
                    return Ctap2Response::error(status);
                }
                self.next_credential_management_credential(channel)
            }
            6 | 7 => {
                if (subcommand == 6 && parameter_fields.len() != 1)
                    || (subcommand == 7 && parameter_fields.len() != 2)
                {
                    return Ctap2Response::error(Ctap2Status::InvalidParameter);
                }
                let Some(CborValue::Map(descriptor)) = field(parameter_fields, 2) else {
                    return Ctap2Response::error(Ctap2Status::MissingParameter);
                };
                if descriptor.len() != 2
                    || text_map_field(descriptor, "type")
                        != Some(&CborValue::Text("public-key".into()))
                    || descriptor.iter().enumerate().any(|(index, (key, _))| {
                        descriptor[..index]
                            .iter()
                            .any(|(previous, _)| previous == key)
                    })
                {
                    return Ctap2Response::error(Ctap2Status::InvalidParameter);
                }
                let Some(CborValue::Bytes(id_bytes)) = text_map_field(descriptor, "id") else {
                    return Ctap2Response::error(Ctap2Status::MissingParameter);
                };
                let Ok(id) = CredentialId::new(id_bytes.to_vec()) else {
                    return Ctap2Response::error(Ctap2Status::InvalidParameter);
                };
                if let Err(status) =
                    self.client_pin
                        .authorize_permission(channel, &auth_message, auth, 0x04)
                {
                    return Ctap2Response::error(status);
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
                if let Err(status) =
                    self.client_pin
                        .authorize(channel, &auth_message, auth, 0x04, Some(rp_id))
                {
                    return Ctap2Response::error(status);
                }
                if subcommand == 6 {
                    let Ok(reference) = std::str::from_utf8(record.key_handle.as_bytes()) else {
                        return Ctap2Response::error(Ctap2Status::Other);
                    };
                    if self
                        .key_store
                        .delete_key(&KeyReference::new(reference))
                        .is_err()
                    {
                        return Ctap2Response::error(Ctap2Status::Other);
                    }
                    match self.store.remove_by_id(&id) {
                        Ok(_) => Ctap2Response::error(Ctap2Status::Success),
                        Err(_) => Ctap2Response::error(Ctap2Status::Other),
                    }
                } else {
                    let Some(CborValue::Map(user)) = field(parameter_fields, 3) else {
                        return Ctap2Response::error(Ctap2Status::MissingParameter);
                    };
                    if user.is_empty()
                        || (text_map_field(user, "name").is_none()
                            && text_map_field(user, "displayName").is_none())
                        || user.iter().any(|(key, _)| {
                            !matches!(key, CborValue::Text(name) if ["id", "name", "displayName"].contains(&name.as_str()))
                        })
                        || user.iter().enumerate().any(|(index, (key, _))| {
                            user[..index].iter().any(|(previous, _)| previous == key)
                        })
                    {
                        return Ctap2Response::error(Ctap2Status::InvalidParameter);
                    }
                    let Some(CborValue::Bytes(user_id)) = text_map_field(user, "id") else {
                        return Ctap2Response::error(Ctap2Status::MissingParameter);
                    };
                    let name = optional_text_field(user, "name");
                    let display_name = optional_text_field(user, "displayName");
                    let (Ok(name), Ok(display_name)) = (name, display_name) else {
                        return Ctap2Response::error(Ctap2Status::InvalidParameter);
                    };
                    match self
                        .store
                        .update_user_labels(&id, user_id, name, display_name)
                    {
                        Ok(()) => Ctap2Response::error(Ctap2Status::Success),
                        Err(_) => Ctap2Response::error(Ctap2Status::InvalidParameter),
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
        state.position += 1;
        rp_response(&entry, entries.len() as u64)
    }

    fn can_start_credential_management(&mut self, channel: u32) -> bool {
        let now = Instant::now();
        self.credential_management
            .retain(|_, state| now < state.expires_at);
        self.credential_management.contains_key(&channel)
            || self.credential_management.len() < MAX_CREDENTIAL_MANAGEMENT_CHANNELS
    }

    fn next_credential_management_credential(&mut self, channel: u32) -> Ctap2Response {
        let Some(state) = self.credential_management.get_mut(&channel) else {
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
        state.position += 1;
        let total = records.len() as u64;
        self.credential_response(&record, total)
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
        auth: Option<[u8; PIN_UV_AUTH_PARAMETER_SIZE]>,
        uv_required: bool,
        permission: u8,
        relying_party_id: &str,
    ) -> Result<bool, Ctap2Status> {
        match auth {
            Some(auth) => {
                self.client_pin.authorize(
                    channel,
                    client_data_hash,
                    &auth,
                    permission,
                    Some(relying_party_id),
                )?;
                Ok(true)
            }
            None if uv_required => Err(Ctap2Status::InvalidOption),
            None => Ok(false),
        }
    }
}

fn parse_pin_auth(
    value: Option<&CborValue>,
    auth_key: u64,
    protocol_key: u64,
) -> Result<Option<[u8; PIN_UV_AUTH_PARAMETER_SIZE]>, Ctap2Status> {
    let Some(CborValue::Map(fields)) = value else {
        return Ok(None);
    };
    if has_duplicate_field(fields, auth_key) || has_duplicate_field(fields, protocol_key) {
        return Err(Ctap2Status::InvalidParameter);
    }
    match (field(fields, auth_key), field(fields, protocol_key)) {
        (None, None) => Ok(None),
        (Some(CborValue::Bytes(auth)), Some(CborValue::Unsigned(protocol)))
            if *protocol == u64::from(PIN_UV_AUTH_PROTOCOL) =>
        {
            auth.as_slice()
                .try_into()
                .map(Some)
                .map_err(|_| Ctap2Status::InvalidParameter)
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
