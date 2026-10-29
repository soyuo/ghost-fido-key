//! Platform-independent MakeCredential checks that require local presence.

use ghost_fido_core::{
    CborValue, CredentialError, CredentialId, CredentialKeyMetadata, CredentialKeyProtection,
    CredentialProtectionPolicy, CredentialRecord, CredentialStore, Ctap2Response, Ctap2Status,
    HmacSecretMaterial, KeyHandle, MakeCredentialRequest,
    encode_make_credential_response_with_extensions,
};
use std::time::Duration;
use zeroize::Zeroize;

use crate::{
    KeyCreationPolicy, KeyStore, PlatformError, PlatformErrorKind, SigningAlgorithm,
    SoftwareKeyConsent, UserVerification, VerificationAction, VerificationDecision,
    VerificationRequest,
};

#[derive(Debug)]
pub enum MakeCredentialExecutionError {
    Platform(PlatformError),
    Credential(CredentialError),
    Randomness,
    ResponseEncoding,
}

impl From<PlatformError> for MakeCredentialExecutionError {
    fn from(error: PlatformError) -> Self {
        Self::Platform(error)
    }
}

impl From<CredentialError> for MakeCredentialExecutionError {
    fn from(error: CredentialError) -> Self {
        Self::Credential(error)
    }
}

/// Executes ES256 MakeCredential with caller-provided key and presence providers.
pub fn register_make_credential(
    request: &MakeCredentialRequest,
    store: &mut CredentialStore,
    key_store: &dyn KeyStore,
    verification: &dyn UserVerification,
    key_policy: KeyCreationPolicy,
    software_key_consent: Option<SoftwareKeyConsent>,
    aaguid: [u8; 16],
    timeout: Duration,
) -> Result<Ctap2Response, MakeCredentialExecutionError> {
    if (request.hmac_secret || request.cred_protect.is_some()) && !store.has_protected_storage() {
        return Ok(Ctap2Response::error(Ctap2Status::UnsupportedOption));
    }
    register_make_credential_with_uv(
        request,
        store,
        key_store,
        verification,
        key_policy,
        software_key_consent,
        aaguid,
        timeout,
        false,
    )
}

/// Executes MakeCredential with the UV flag set only after PIN token validation.
pub fn register_make_credential_with_uv(
    request: &MakeCredentialRequest,
    store: &mut CredentialStore,
    key_store: &dyn KeyStore,
    verification: &dyn UserVerification,
    key_policy: KeyCreationPolicy,
    software_key_consent: Option<SoftwareKeyConsent>,
    aaguid: [u8; 16],
    timeout: Duration,
    user_verified: bool,
) -> Result<Ctap2Response, MakeCredentialExecutionError> {
    if (request.hmac_secret || request.cred_protect.is_some()) && !store.has_protected_storage() {
        return Ok(Ctap2Response::error(Ctap2Status::UnsupportedOption));
    }
    if !request
        .public_key_credential_parameters
        .iter()
        .any(|parameter| parameter.algorithm == -7)
    {
        return Ok(Ctap2Response::error(Ctap2Status::UnsupportedAlgorithm));
    }
    if (request.options.user_verification == Some(true) && !user_verified)
        || request.options.user_presence == Some(false)
    {
        return Ok(Ctap2Response::error(
            if request.options.user_verification == Some(true) {
                Ctap2Status::PinUvAuthTokenRequired
            } else {
                Ctap2Status::UnsupportedOption
            },
        ));
    }

    if request.has_excluded_credential_requiring_uv(store) && !user_verified {
        return Ok(Ctap2Response::error(Ctap2Status::PinUvAuthTokenRequired));
    }

    if let Some(response) = check_credential_exclusion(request, store, verification, timeout)? {
        return Ok(response);
    }

    let verification_request = VerificationRequest {
        relying_party_id: request.rp.id.clone(),
        relying_party_name: request.rp.name.clone(),
        action: VerificationAction::RegisterCredential,
    };
    match verification.request_confirmation(&verification_request, timeout) {
        Ok(VerificationDecision::Approved) => {}
        Ok(VerificationDecision::Rejected) => {
            return Ok(Ctap2Response::error(Ctap2Status::OperationDenied));
        }
        Ok(VerificationDecision::Cancelled) => {
            return Ok(Ctap2Response::error(Ctap2Status::KeepaliveCancel));
        }
        Err(error) if error.kind == PlatformErrorKind::Timeout => {
            return Ok(Ctap2Response::error(Ctap2Status::UserActionTimeout));
        }
        Err(error) => return Err(error.into()),
    }

    let mut credential_id_bytes = [0; 16];
    getrandom::fill(&mut credential_id_bytes)
        .map_err(|_| MakeCredentialExecutionError::Randomness)?;
    let mut hmac_secret_with_uv = [0; 32];
    let mut hmac_secret_without_uv = [0; 32];
    let hmac_secret = if request.hmac_secret {
        if getrandom::fill(&mut hmac_secret_with_uv).is_err() {
            hmac_secret_with_uv.zeroize();
            return Err(MakeCredentialExecutionError::Randomness);
        }
        if getrandom::fill(&mut hmac_secret_without_uv).is_err() {
            hmac_secret_with_uv.zeroize();
            return Err(MakeCredentialExecutionError::Randomness);
        }
        Some(HmacSecretMaterial::new(
            hmac_secret_with_uv,
            hmac_secret_without_uv,
        ))
    } else {
        None
    };
    hmac_secret_with_uv.zeroize();
    hmac_secret_without_uv.zeroize();

    let created =
        key_store.create_signing_key(SigningAlgorithm::Es256, key_policy, software_key_consent)?;
    let key_handle = match KeyHandle::new(
        created
            .reference
            .as_provider_reference()
            .as_bytes()
            .to_vec(),
    ) {
        Ok(handle) => handle,
        Err(error) => {
            return Err(cleanup_failed_creation(
                key_store,
                &created.reference,
                error.into(),
            ));
        }
    };
    let credential_id = match CredentialId::new(credential_id_bytes.to_vec()) {
        Ok(id) => id,
        Err(error) => {
            return Err(cleanup_failed_creation(
                key_store,
                &created.reference,
                error.into(),
            ));
        }
    };
    let mut extension_values = Vec::new();
    if request.hmac_secret {
        extension_values.push((CborValue::Text("hmac-secret".into()), CborValue::Bool(true)));
    }
    if let Some(policy) = request.cred_protect {
        extension_values.push((
            CborValue::Text("credProtect".into()),
            CborValue::Unsigned(u64::from(policy as u8)),
        ));
    }
    let extensions = (!extension_values.is_empty()).then_some(CborValue::Map(extension_values));
    let response = match encode_make_credential_response_with_extensions(
        request.rp_id_hash(),
        aaguid,
        credential_id.as_bytes(),
        &created.public_key,
        user_verified,
        extensions,
    ) {
        Ok(response) => response,
        Err(_) => {
            return Err(cleanup_failed_creation(
                key_store,
                &created.reference,
                MakeCredentialExecutionError::ResponseEncoding,
            ));
        }
    };
    let record = CredentialRecord {
        id: credential_id,
        rp_id_hash: request.rp_id_hash(),
        relying_party_id: Some(request.rp.id.clone()),
        user_handle: request.user.id.clone(),
        user_name: request.user.name.clone(),
        user_display_name: request.user.display_name.clone(),
        key_handle,
        public_key: Some(created.public_key.clone()),
        hmac_secret,
        cred_protect: request
            .cred_protect
            .unwrap_or(CredentialProtectionPolicy::UserVerificationOptional),
        key_metadata: CredentialKeyMetadata {
            protection: match created.metadata.protection {
                crate::KeyProtection::HardwareBacked => CredentialKeyProtection::HardwareBacked,
                crate::KeyProtection::OsProtected => CredentialKeyProtection::OsProtected,
                crate::KeyProtection::Software => CredentialKeyProtection::Software,
            },
            exportable: created.metadata.exportable,
        },
        discoverable: request.options.resident_key.unwrap_or(false),
        creation_order: 0,
        sign_count: 0,
    };
    if let Err(error) = store.register(record) {
        return Err(cleanup_failed_creation(
            key_store,
            &created.reference,
            error.into(),
        ));
    }
    Ok(response)
}

fn cleanup_failed_creation(
    key_store: &dyn KeyStore,
    reference: &crate::KeyReference,
    original_error: MakeCredentialExecutionError,
) -> MakeCredentialExecutionError {
    match key_store.delete_key(reference) {
        Ok(()) => original_error,
        Err(cleanup_error) => MakeCredentialExecutionError::Platform(cleanup_error),
    }
}

/// Checks a MakeCredential exclude list without disclosing a match before a
/// local presence interaction completes.
///
/// A timeout after the provider has waited for the requested duration returns
/// CredentialExcluded, matching CTAP's duplicate-registration behavior. Other
/// provider errors fail closed and do not reveal whether a credential matched.
pub fn check_credential_exclusion(
    request: &MakeCredentialRequest,
    store: &CredentialStore,
    verification: &dyn UserVerification,
    timeout: Duration,
) -> Result<Option<Ctap2Response>, PlatformError> {
    if !request.has_excluded_credential(store) {
        return Ok(None);
    }

    let verification_request = VerificationRequest {
        relying_party_id: request.rp.id.clone(),
        relying_party_name: request.rp.name.clone(),
        action: VerificationAction::CredentialExclusionCheck,
    };

    match verification.request_confirmation(&verification_request, timeout) {
        Ok(VerificationDecision::Approved | VerificationDecision::Rejected) => {}
        Ok(VerificationDecision::Cancelled) => {
            return Ok(Some(Ctap2Response::error(Ctap2Status::KeepaliveCancel)));
        }
        Err(error) if error.kind == PlatformErrorKind::Timeout => {}
        Err(error) => return Err(error),
    }

    Ok(Some(Ctap2Response {
        status: Ctap2Status::CredentialExcluded,
        payload: Vec::new(),
    }))
}
