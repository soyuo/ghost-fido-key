//! CTAP2 command routing across the platform-independent core and providers.

use std::time::Duration;

use ghost_fido_core::{
    CredentialStore, Ctap2Command, Ctap2Handler, Ctap2Request, Ctap2Response, Ctap2Status,
    GetAssertionRequest, GetInfoError, GetInfoProfile, MakeCredentialRequest,
};

use crate::{
    GetAssertionExecutionError, KeyCreationPolicy, KeyStore, MakeCredentialExecutionError,
    SoftwareKeyConsent, UserVerification, execute_get_assertion, register_make_credential,
};

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
        })
    }

    pub fn handle(
        &mut self,
        request: &Ctap2Request,
    ) -> Result<Ctap2Response, AuthenticatorServiceError> {
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
                execute_get_assertion(
                    &typed,
                    self.store,
                    self.key_store,
                    self.verification,
                    self.config.request_timeout,
                )
                .map_err(AuthenticatorServiceError::GetAssertion)
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
