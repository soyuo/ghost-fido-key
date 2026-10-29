//! CTAP2 command routing across the platform-independent core and providers.

use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

use ghost_fido_core::{
    CredentialId, CredentialStore, Ctap2Command, Ctap2Request, Ctap2Response, Ctap2Status,
    GetAssertionRequest, GetInfoError, GetInfoHandler, GetInfoProfile, MakeCredentialRequest,
};

use crate::{
    GetAssertionExecutionError, KeyCreationPolicy, KeyReference, KeyStore,
    MakeCredentialExecutionError, PlatformErrorKind, SoftwareKeyConsent, UserVerification,
    VerificationAction, VerificationDecision, VerificationRequest, execute_get_assertion,
    execute_next_assertion, register_make_credential,
};

const ASSERTION_CONTINUATION_TIMEOUT: Duration = Duration::from_secs(30);
const RESET_POWER_UP_WINDOW: Duration = Duration::from_secs(10);
const LEGACY_CHANNEL: u32 = u32::MAX;

struct AssertionContinuation {
    request: GetAssertionRequest,
    credentials: VecDeque<CredentialId>,
    expires_at: Instant,
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
    get_info_handler: GetInfoHandler,
    store: &'a mut CredentialStore,
    key_store: &'a dyn KeyStore,
    verification: &'a dyn UserVerification,
    config: AuthenticatorServiceConfig,
    assertion_continuations: BTreeMap<u32, AssertionContinuation>,
    started_at: Instant,
}

impl<'a> AuthenticatorService<'a> {
    pub fn new(
        store: &'a mut CredentialStore,
        key_store: &'a dyn KeyStore,
        verification: &'a dyn UserVerification,
        config: AuthenticatorServiceConfig,
    ) -> Result<Self, GetInfoError> {
        let get_info_handler = GetInfoHandler::new(&config.get_info)?;
        Ok(Self {
            get_info_handler,
            store,
            key_store,
            verification,
            config,
            assertion_continuations: BTreeMap::new(),
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
        match command {
            Ctap2Command::GetInfo => Ok(self.get_info_handler.handle(&payload)),
            Ctap2Command::MakeCredential => {
                let typed = match decoded_payload.map_or_else(
                    || MakeCredentialRequest::decode(&payload),
                    MakeCredentialRequest::decode_value,
                ) {
                    Ok(request) => request,
                    Err(error) => return Ok(Ctap2Response::error(error.status())),
                };
                register_make_credential(
                    &typed,
                    self.store,
                    self.key_store,
                    self.verification,
                    self.config.key_creation_policy,
                    self.config.software_key_consent,
                    self.config.aaguid,
                    self.config.request_timeout,
                )
                .map_err(AuthenticatorServiceError::MakeCredential)
            }
            Ctap2Command::GetAssertion => {
                let typed = match decoded_payload.map_or_else(
                    || GetAssertionRequest::decode(&payload),
                    GetAssertionRequest::decode_value,
                ) {
                    Ok(request) => request,
                    Err(error) => return Ok(Ctap2Response::error(error.status())),
                };
                let execution = execute_get_assertion(
                    &typed,
                    self.store,
                    self.key_store,
                    self.verification,
                    self.config.request_timeout,
                )
                .map_err(AuthenticatorServiceError::GetAssertion)?;
                if !execution.remaining_credentials.is_empty() {
                    self.assertion_continuations.insert(
                        channel,
                        AssertionContinuation {
                            request: typed,
                            credentials: execution.remaining_credentials.into(),
                            expires_at: Instant::now() + ASSERTION_CONTINUATION_TIMEOUT,
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
                let result = execute_next_assertion(
                    &continuation.request,
                    &credential_id,
                    self.store,
                    self.key_store,
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
    }
}
