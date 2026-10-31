//! Platform-independent MakeCredential checks that require local presence.

use ghost_fido_core::{
    CborValue, CredentialError, CredentialId, CredentialKeyMetadata, CredentialKeyProtection,
    CredentialProtectionPolicy, CredentialRecord, CredentialStore, Ctap2Response, Ctap2Status,
    HmacSecretMaterial, KeyHandle, LargeBlobKey, MakeCredentialRequest,
    encode_make_credential_response_with_extensions_and_large_blob_key,
};
use std::time::Duration;
use zeroize::Zeroizing;

use crate::{
    CreatedSigningKey, KeyCreationPolicy, KeyStore, PlatformError, PlatformErrorKind,
    SigningAlgorithm, SoftwareKeyConsent, UserVerification, VerificationAction,
    VerificationDecision, VerificationRequest,
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
    if (request.hmac_secret || request.cred_protect.is_some() || request.large_blob_key)
        && !store.has_protected_storage()
    {
        return Ok(Ctap2Response::error(Ctap2Status::UnsupportedOption));
    }
    if request.large_blob_key && !store.supports_large_blobs() {
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
    register_make_credential_with_uv_and_presence_callback(
        request,
        store,
        key_store,
        verification,
        key_policy,
        software_key_consent,
        aaguid,
        timeout,
        user_verified,
        &mut || {},
    )
}

pub(crate) fn register_make_credential_with_uv_and_presence_callback(
    request: &MakeCredentialRequest,
    store: &mut CredentialStore,
    key_store: &dyn KeyStore,
    verification: &dyn UserVerification,
    key_policy: KeyCreationPolicy,
    software_key_consent: Option<SoftwareKeyConsent>,
    aaguid: [u8; 16],
    timeout: Duration,
    user_verified: bool,
    on_user_presence: &mut dyn FnMut(),
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
    if request.options.user_presence == Some(false) {
        return Ok(Ctap2Response::error(Ctap2Status::InvalidOption));
    }
    if request.options.user_verification == Some(true) && !user_verified {
        return Ok(Ctap2Response::error(Ctap2Status::PinUvAuthTokenRequired));
    }

    if request.has_excluded_credential_requiring_uv(store) && !user_verified {
        return Ok(Ctap2Response::error(Ctap2Status::PinUvAuthTokenRequired));
    }

    if let Some(response) = check_credential_exclusion_with_presence_callback(
        request,
        store,
        verification,
        timeout,
        on_user_presence,
    )? {
        return Ok(response);
    }

    let verification_request = VerificationRequest {
        relying_party_id: request.rp.id.clone(),
        relying_party_name: request.rp.name.clone(),
        action: VerificationAction::RegisterCredential,
    };
    match verification.request_confirmation(&verification_request, timeout) {
        Ok(VerificationDecision::Approved) => on_user_presence(),
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
    let mut hmac_secret_with_uv = Zeroizing::new([0; 32]);
    let mut hmac_secret_without_uv = Zeroizing::new([0; 32]);
    let hmac_secret = if request.hmac_secret {
        if getrandom::fill(&mut hmac_secret_with_uv[..]).is_err() {
            return Err(MakeCredentialExecutionError::Randomness);
        }
        if getrandom::fill(&mut hmac_secret_without_uv[..]).is_err() {
            return Err(MakeCredentialExecutionError::Randomness);
        }
        Some(HmacSecretMaterial::new(
            hmac_secret_with_uv,
            hmac_secret_without_uv,
        ))
    } else {
        None
    };
    let large_blob_key = if request.large_blob_key {
        let mut bytes = Zeroizing::new([0; 32]);
        if getrandom::fill(&mut bytes[..]).is_err() {
            return Err(MakeCredentialExecutionError::Randomness);
        }
        Some(LargeBlobKey::new(bytes))
    } else {
        None
    };
    let cred_blob = request
        .cred_blob
        .as_ref()
        .filter(|blob| {
            blob.as_bytes().len() <= ghost_fido_core::MAX_CREDENTIAL_BLOB_LENGTH
                && request.options.resident_key == Some(true)
                && store.has_protected_storage()
        })
        .cloned();

    let (created, key_handle) =
        match create_journaled_signing_key(store, key_store, key_policy, software_key_consent) {
            Ok(created) => created,
            Err(error)
                if key_policy == KeyCreationPolicy::PlatformProtectedOnly
                    && error.kind == PlatformErrorKind::PlatformKeyProtectionUnavailable =>
            {
                let fallback_request = VerificationRequest {
                    relying_party_id: request.rp.id.clone(),
                    relying_party_name: request.rp.name.clone(),
                    action: VerificationAction::SoftwareKeyFallback,
                };
                match verification.request_confirmation(&fallback_request, timeout) {
                    Ok(VerificationDecision::Approved) => {
                        let consent = SoftwareKeyConsent::confirm_user_acceptance(true)
                            .expect("accepted fallback creates a consent marker");
                        create_journaled_signing_key(
                            store,
                            key_store,
                            KeyCreationPolicy::SoftwareKeyAfterExplicitConsent,
                            Some(consent),
                        )?
                    }
                    Ok(VerificationDecision::Rejected) => {
                        return Ok(Ctap2Response::error(Ctap2Status::OperationDenied));
                    }
                    Ok(VerificationDecision::Cancelled) => {
                        return Ok(Ctap2Response::error(Ctap2Status::KeepaliveCancel));
                    }
                    Err(error) if error.kind == PlatformErrorKind::Timeout => {
                        return Ok(Ctap2Response::error(Ctap2Status::KeepaliveCancel));
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Err(error) => return Err(error.into()),
        };
    let credential_id = match CredentialId::new(credential_id_bytes.to_vec()) {
        Ok(id) => id,
        Err(error) => {
            return Err(cleanup_failed_creation(
                store,
                key_store,
                &created.reference,
                &key_handle,
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
    if request.cred_blob.is_some() {
        extension_values.push((
            CborValue::Text("credBlob".into()),
            CborValue::Bool(cred_blob.is_some()),
        ));
    }
    if request.min_pin_length
        && store
            .pin_state()
            .min_pin_length_rp_ids()
            .iter()
            .any(|rp_id| rp_id == &request.rp.id)
    {
        extension_values.push((
            CborValue::Text("minPinLength".into()),
            CborValue::Unsigned(u64::from(store.pin_state().min_pin_length())),
        ));
    }
    let extensions = (!extension_values.is_empty()).then_some(CborValue::Map(extension_values));
    let response = match encode_make_credential_response_with_extensions_and_large_blob_key(
        request.rp_id_hash(),
        aaguid,
        credential_id.as_bytes(),
        &created.public_key,
        user_verified,
        extensions,
        large_blob_key.as_ref(),
    ) {
        Ok(response) => response,
        Err(_) => {
            return Err(cleanup_failed_creation(
                store,
                key_store,
                &created.reference,
                &key_handle,
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
        key_handle: key_handle.clone(),
        public_key: Some(created.public_key.clone()),
        hmac_secret,
        large_blob_key,
        cred_blob,
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
    if let Err(error) = store.register_created_key(record, &key_handle) {
        return Err(cleanup_failed_creation(
            store,
            key_store,
            &created.reference,
            &key_handle,
            error.into(),
        ));
    }
    Ok(response)
}

fn cleanup_failed_creation(
    store: &mut CredentialStore,
    key_store: &dyn KeyStore,
    reference: &crate::KeyReference,
    key_handle: &KeyHandle,
    original_error: MakeCredentialExecutionError,
) -> MakeCredentialExecutionError {
    match key_store.delete_key(reference) {
        Ok(()) => match store.mark_provider_key_deleted(key_handle) {
            Ok(()) => original_error,
            Err(error) => MakeCredentialExecutionError::Platform(PlatformError::new(
                PlatformErrorKind::KeyStoreUnavailable,
                crate::HostPlatform::current(),
                format!(
                    "provider key was deleted but its cleanup journal could not be cleared: {error:?}"
                ),
            )),
        },
        Err(cleanup_error) => MakeCredentialExecutionError::Platform(cleanup_error),
    }
}

fn create_journaled_signing_key(
    store: &mut CredentialStore,
    key_store: &dyn KeyStore,
    policy: KeyCreationPolicy,
    consent: Option<SoftwareKeyConsent>,
) -> Result<(CreatedSigningKey, KeyHandle), PlatformError> {
    let reference = key_store.allocate_signing_key_reference(policy, consent)?;
    let key_handle = KeyHandle::new(reference.as_provider_reference().as_bytes().to_vec())
        .map_err(|error| {
            PlatformError::new(
                PlatformErrorKind::KeyStoreUnavailable,
                crate::HostPlatform::current(),
                format!("{error:?}"),
            )
        })?;
    store
        .begin_provider_key_creation(key_handle.clone())
        .map_err(|error| {
            PlatformError::new(
                PlatformErrorKind::KeyStoreUnavailable,
                crate::HostPlatform::current(),
                format!("could not persist provider-key creation intent: {error:?}"),
            )
        })?;
    match key_store.create_signing_key(&reference, SigningAlgorithm::Es256, policy, consent) {
        Ok(created) if created.reference == reference => Ok((created, key_handle)),
        Ok(created) => {
            let _ = key_store.delete_key(&created.reference);
            Err(PlatformError::new(
                PlatformErrorKind::KeyStoreUnavailable,
                crate::HostPlatform::current(),
                "provider created a key under a different reference than the reserved journal",
            ))
        }
        Err(error) if error.kind == PlatformErrorKind::PlatformKeyProtectionUnavailable => {
            // Providers use this result only when protection is unavailable
            // before a key is created, or after their own incomplete-key
            // cleanup has succeeded.
            store
                .mark_provider_key_deleted(&key_handle)
                .map_err(|journal_error| {
                    PlatformError::new(
                        PlatformErrorKind::KeyStoreUnavailable,
                        crate::HostPlatform::current(),
                        format!("could not clear unused provider-key intent: {journal_error:?}"),
                    )
                })?;
            Err(error)
        }
        Err(error) => match key_store.delete_key(&reference) {
            Ok(()) => match store.mark_provider_key_deleted(&key_handle) {
                Ok(()) => Err(error),
                Err(journal_error) => Err(PlatformError::new(
                    PlatformErrorKind::KeyStoreUnavailable,
                    crate::HostPlatform::current(),
                    format!(
                        "provider key was absent but its cleanup journal could not be cleared: {journal_error:?}"
                    ),
                )),
            },
            Err(cleanup_error) => Err(cleanup_error),
        },
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
    check_credential_exclusion_with_presence_callback(
        request,
        store,
        verification,
        timeout,
        &mut || {},
    )
}

fn check_credential_exclusion_with_presence_callback(
    request: &MakeCredentialRequest,
    store: &CredentialStore,
    verification: &dyn UserVerification,
    timeout: Duration,
    on_user_presence: &mut dyn FnMut(),
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
        Ok(VerificationDecision::Approved) => on_user_presence(),
        Ok(VerificationDecision::Rejected) => {}
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
