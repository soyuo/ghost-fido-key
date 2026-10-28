//! CTAP2 command routing across the platform-independent core and providers.

use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

use ghost_fido_core::{
    CredentialId, CredentialStore, Ctap2Command, Ctap2Handler, Ctap2Request, Ctap2Response,
    Ctap2Status, GetAssertionRequest, GetInfoError, GetInfoProfile, MakeCredentialRequest,
};

use crate::{
    GetAssertionExecutionError, KeyCreationPolicy, KeyStore, MakeCredentialExecutionError,
    SoftwareKeyConsent, UserVerification, execute_get_assertion, execute_next_assertion,
    register_make_credential,
};

const ASSERTION_CONTINUATION_TIMEOUT: Duration = Duration::from_secs(30);
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
    get_info_handler: Ctap2Handler,
    store: &'a mut CredentialStore,
    key_store: &'a dyn KeyStore,
    verification: &'a dyn UserVerification,
    config: AuthenticatorServiceConfig,
    assertion_continuations: BTreeMap<u32, AssertionContinuation>,
}

impl<'a> AuthenticatorService<'a> {
    pub fn new(
        store: &'a mut CredentialStore,
        key_store: &'a dyn KeyStore,
        verification: &'a dyn UserVerification,
        config: AuthenticatorServiceConfig,
    ) -> Result<Self, GetInfoError> {
        let get_info_handler = Ctap2Handler::new(&config.get_info)?;
        Ok(Self {
            get_info_handler,
            store,
            key_store,
            verification,
            config,
            assertion_continuations: BTreeMap::new(),
        })
    }

    pub fn handle(
        &mut self,
        request: &Ctap2Request,
    ) -> Result<Ctap2Response, AuthenticatorServiceError> {
        self.handle_on_channel(LEGACY_CHANNEL, request)
    }

    /// Handles one CTAP2 request and scopes any GetNextAssertion state to its CTAPHID channel.
    pub fn handle_on_channel(
        &mut self,
        channel: u32,
        request: &Ctap2Request,
    ) -> Result<Ctap2Response, AuthenticatorServiceError> {
        if request.command != Ctap2Command::GetNextAssertion {
            self.assertion_continuations.remove(&channel);
        }
        match request.command {
            Ctap2Command::GetInfo => Ok(self.get_info_handler.handle(request)),
            Ctap2Command::MakeCredential => {
                let typed = match MakeCredentialRequest::decode(&request.payload) {
                    Ok(request) => request,
                    Err(error) => return Ok(protocol_error(error.status())),
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
                let typed = match GetAssertionRequest::decode(&request.payload) {
                    Ok(request) => request,
                    Err(error) => return Ok(protocol_error(error.status())),
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
                if !request.payload.is_empty() {
                    return Ok(protocol_error(Ctap2Status::InvalidLength));
                }
                let Some(mut continuation) = self.assertion_continuations.remove(&channel) else {
                    return Ok(protocol_error(Ctap2Status::NotAllowed));
                };
                if Instant::now() >= continuation.expires_at {
                    return Ok(protocol_error(Ctap2Status::NotAllowed));
                }
                let Some(credential_id) = continuation.credentials.pop_front() else {
                    return Ok(protocol_error(Ctap2Status::NotAllowed));
                };
                let result = execute_next_assertion(
                    &continuation.request,
                    &credential_id,
                    self.store,
                    self.key_store,
                )
                .map_err(AuthenticatorServiceError::GetAssertion)?;
                if result.status != Ctap2Status::Success {
                    return Ok(protocol_error(Ctap2Status::NotAllowed));
                }
                if !continuation.credentials.is_empty() {
                    self.assertion_continuations.insert(channel, continuation);
                }
                Ok(result)
            }
            _ => Ok(protocol_error(Ctap2Status::InvalidCommand)),
        }
    }
}

fn protocol_error(status: Ctap2Status) -> Ctap2Response {
    Ctap2Response {
        status,
        payload: Vec::new(),
    }
}
