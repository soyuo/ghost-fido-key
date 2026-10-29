//! CTAP2 command routing across the platform-independent core and providers.

use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

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
    VerificationAction, VerificationDecision, VerificationRequest, execute_next_assertion_with_uv,
};

const ASSERTION_CONTINUATION_TIMEOUT: Duration = Duration::from_secs(30);
const RESET_POWER_UP_WINDOW: Duration = Duration::from_secs(10);
const LEGACY_CHANNEL: u32 = u32::MAX;

struct AssertionContinuation {
    request: GetAssertionRequest,
    credentials: VecDeque<CredentialId>,
    expires_at: Instant,
    user_verified: bool,
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
    relying_party_id: Option<String>,
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
        relying_party_id: &str,
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
        if token.permissions & permission == 0
            || token
                .relying_party_id
                .as_deref()
                .is_some_and(|allowed| allowed != relying_party_id)
        {
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

        match subcommand {
            1 => response_map(vec![(
                3,
                CborValue::Unsigned(u64::from(store.pin_state().retries())),
            )]),
            2 => {
                let agreement = PinKeyAgreement::generate();
                let public_key = match decode_cbor(&agreement.cose_public_key()) {
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
    ) -> Result<[u8; 32], Ctap2Status> {
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
        let Ok(mut pin) = pin else {
            return Ctap2Response::error(Ctap2Status::PinPolicyViolation);
        };
        let verifier = client_pin_hash(&pin);
        pin.zeroize();
        match store.set_pin_verifier(Some(verifier)) {
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
        let Some(verifier) = store.pin_state().verifier() else {
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
        let mut encrypted_hash = hash_encrypted.to_vec();
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
            encrypted_hash.zeroize();
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
        encrypted_hash.zeroize();
        let mut encrypted_pin = new_encrypted.to_vec();
        let decrypted = client_pin_decrypt_pin(&secret, &mut encrypted_pin);
        secret.zeroize();
        let Ok(mut pin) = decrypted else {
            return Ctap2Response::error(Ctap2Status::PinPolicyViolation);
        };
        let new_verifier = client_pin_hash(&pin);
        pin.zeroize();
        match store.set_pin_verifier(Some(new_verifier)) {
            Ok(()) => Ctap2Response::error(Ctap2Status::Success),
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
        if permissions == 0 || permissions & !0x03 != 0 {
            return Ctap2Response::error(Ctap2Status::UnauthorizedPermission);
        }
        let relying_party_id = match field(fields, 10) {
            None => None,
            Some(CborValue::Text(value)) if !value.is_empty() => Some(value.clone()),
            Some(_) => return Ctap2Response::error(Ctap2Status::InvalidParameter),
        };
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
        let Some(verifier) = store.pin_state().verifier() else {
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
        let mut decrypted_hash = encrypted.to_vec();
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
            decrypted_hash.zeroize();
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
        decrypted_hash.zeroize();
        if store.set_pin_retries(8).is_err() {
            secret.zeroize();
            return Ctap2Response::error(Ctap2Status::Other);
        }
        let mut token = [0_u8; 32];
        if getrandom::fill(&mut token).is_err() {
            secret.zeroize();
            return Ctap2Response::error(Ctap2Status::Other);
        }
        let mut encrypted_token = token.to_vec();
        if client_pin_encrypt(&secret, &mut encrypted_token).is_err() {
            secret.zeroize();
            token.zeroize();
            return Ctap2Response::error(Ctap2Status::Other);
        }
        secret.zeroize();
        self.tokens.insert(
            channel,
            PinTokenEntry {
                value: token,
                expires_at: Instant::now() + PIN_PROTOCOL_TIMEOUT,
                permissions,
                relying_party_id,
            },
        );
        response_map(vec![(2, CborValue::Bytes(encrypted_token))])
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
    Ctap2Response {
        status: Ctap2Status::Success,
        payload: encode_cbor(&value),
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

    /// Handles one CTAP2 request and scopes any GetNextAssertion state to its CTAPHID channel.
    pub fn handle_on_channel(
        &mut self,
        channel: u32,
        request: Ctap2Request,
    ) -> Result<Ctap2Response, AuthenticatorServiceError> {
        let (command, payload, decoded_payload) = request.into_parts();
        if command != Ctap2Command::GetNextAssertion {
            self.assertion_continuations.remove(&channel);
        }
        self.client_pin.expire();
        match command {
            Ctap2Command::GetInfo => {
                if !payload.is_empty() {
                    return Ok(Ctap2Response::error(Ctap2Status::InvalidLength));
                }
                let mut profile = self.config.get_info.clone();
                let pin_is_set = self.store.pin_state().verifier().is_some();
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
                profile.pin_uv_auth_protocols = vec![u64::from(PIN_UV_AUTH_PROTOCOL)];
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
                let user_verified = match self.verify_pin_authorization(
                    channel,
                    &typed.client_data_hash,
                    pin_auth,
                    typed.options.user_verification == Some(true),
                    0x02,
                    &typed.rp_id,
                ) {
                    Ok(value) => value,
                    Err(status) => return Ok(Ctap2Response::error(status)),
                };
                let execution = crate::execute_get_assertion_with_uv(
                    &typed,
                    self.store,
                    self.key_store,
                    self.verification,
                    self.config.request_timeout,
                    user_verified,
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
                        },
                    );
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
                let result = execute_next_assertion_with_uv(
                    &continuation.request,
                    &credential_id,
                    self.store,
                    self.key_store,
                    continuation.user_verified,
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
                let references = match self
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
                for reference in &references {
                    if self.key_store.delete_key(reference).is_err() {
                        return Ok(Ctap2Response::error(Ctap2Status::Other));
                    }
                }
                if self.store.clear().is_err() {
                    return Ok(Ctap2Response::error(Ctap2Status::Other));
                }
                self.assertion_continuations.clear();
                self.client_pin.clear_all();
                Ok(Ctap2Response::error(Ctap2Status::Success))
            }
            _ => Ok(Ctap2Response::error(Ctap2Status::InvalidCommand)),
        }
    }

    pub(crate) fn clear_channel(&mut self, channel: u32) {
        self.assertion_continuations.remove(&channel);
    }

    /// Clears per-channel state after the transport reports cancellation or expiry.
    pub fn cancel_channel(&mut self, channel: u32) {
        self.clear_channel(channel);
        self.client_pin.clear_channel(channel);
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
                    relying_party_id,
                )?;
                Ok(true)
            }
            None if uv_required => Err(Ctap2Status::PinUvAuthTokenRequired),
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
