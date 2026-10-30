//! Single-credential CTAP2 GetAssertion execution.

use std::{cmp::Reverse, time::Duration};

use ghost_fido_core::{
    CborValue, CredentialError, CredentialId, CredentialProtectionPolicy, CredentialStore,
    Ctap2Response, Ctap2Status, GetAssertionRequest, KeyHandle, PinUvAuthSharedSecret,
    client_pin_process_hmac_secret_with_protocol,
    client_pin_validate_hmac_secret_request_with_protocol,
    encode_get_assertion_response_with_count_and_presence_and_uv_and_extensions_and_large_blob_key,
    get_assertion_authenticator_data_with_presence_and_uv,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    KeyReference, KeyStore, PlatformError, PlatformErrorKind, SigningAlgorithm, UserVerification,
    VerificationAction, VerificationDecision, VerificationRequest,
};

#[derive(Debug)]
pub enum GetAssertionExecutionError {
    Platform(PlatformError),
    Credential(CredentialError),
    InvalidKeyReference,
    InvalidSignature,
    ResponseEncoding,
}

#[derive(Debug)]
pub struct GetAssertionExecution {
    pub response: Ctap2Response,
    pub remaining_credentials: Vec<CredentialId>,
}

impl From<PlatformError> for GetAssertionExecutionError {
    fn from(error: PlatformError) -> Self {
        Self::Platform(error)
    }
}

impl From<CredentialError> for GetAssertionExecutionError {
    fn from(error: CredentialError) -> Self {
        Self::Credential(error)
    }
}

/// Approves and signs a GetAssertion request, retaining any continuation credentials.
pub fn execute_get_assertion(
    request: &GetAssertionRequest,
    store: &mut CredentialStore,
    key_store: &dyn KeyStore,
    verification: &dyn UserVerification,
    timeout: Duration,
) -> Result<GetAssertionExecution, GetAssertionExecutionError> {
    execute_get_assertion_with_uv_and_hmac_secret(
        request,
        store,
        key_store,
        verification,
        timeout,
        false,
        None,
    )
}

pub fn execute_get_assertion_with_uv(
    request: &GetAssertionRequest,
    store: &mut CredentialStore,
    key_store: &dyn KeyStore,
    verification: &dyn UserVerification,
    timeout: Duration,
    user_verified: bool,
) -> Result<GetAssertionExecution, GetAssertionExecutionError> {
    execute_get_assertion_with_uv_and_hmac_secret(
        request,
        store,
        key_store,
        verification,
        timeout,
        user_verified,
        None,
    )
}

pub fn execute_get_assertion_with_uv_and_hmac_secret(
    request: &GetAssertionRequest,
    store: &mut CredentialStore,
    key_store: &dyn KeyStore,
    verification: &dyn UserVerification,
    timeout: Duration,
    user_verified: bool,
    hmac_secret_shared_secret: Option<&PinUvAuthSharedSecret>,
) -> Result<GetAssertionExecution, GetAssertionExecutionError> {
    execute_get_assertion_with_uv_and_hmac_secret_and_presence_callback(
        request,
        store,
        key_store,
        verification,
        timeout,
        user_verified,
        hmac_secret_shared_secret,
        &mut || {},
    )
}

pub(crate) fn execute_get_assertion_with_uv_and_hmac_secret_and_presence_callback(
    request: &GetAssertionRequest,
    store: &mut CredentialStore,
    key_store: &dyn KeyStore,
    verification: &dyn UserVerification,
    timeout: Duration,
    user_verified: bool,
    hmac_secret_shared_secret: Option<&PinUvAuthSharedSecret>,
    on_user_presence: &mut dyn FnMut(),
) -> Result<GetAssertionExecution, GetAssertionExecutionError> {
    if request.large_blob_key && !store.supports_large_blobs() {
        return Ok(single_response(Ctap2Response::error(
            Ctap2Status::UnsupportedOption,
        )));
    }
    if request.options.user_verification == Some(true) && !user_verified {
        return Ok(single_response(Ctap2Response::error(
            Ctap2Status::PinUvAuthTokenRequired,
        )));
    }

    let mut matching = request.find_credentials(store);
    if matching.is_empty() {
        return Ok(single_response(Ctap2Response::error(
            Ctap2Status::NoCredentials,
        )));
    }
    let blocked_by_policy = matching.iter().any(|record| {
        record.cred_protect == CredentialProtectionPolicy::UserVerificationRequired
            || (record.cred_protect
                == CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList
                && request.allow_list.is_none())
    });
    matching.retain(|record| {
        user_verified
            || match record.cred_protect {
                CredentialProtectionPolicy::UserVerificationOptional => true,
                CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList => {
                    request.allow_list.is_some()
                }
                CredentialProtectionPolicy::UserVerificationRequired => false,
            }
    });
    if matching.is_empty() {
        return Ok(single_response(Ctap2Response::error(
            if blocked_by_policy {
                Ctap2Status::PinUvAuthTokenRequired
            } else {
                Ctap2Status::NoCredentials
            },
        )));
    }
    if request.allow_list.is_none() {
        matching.sort_by_key(|record| Reverse(record.creation_order));
    }

    let credential_count = matching.len();
    let credential_id = matching[0].id.clone();
    let remaining_credentials = if request.allow_list.is_none() {
        matching
            .iter()
            .skip(1)
            .map(|record| record.id.clone())
            .collect()
    } else {
        Vec::new()
    };
    drop(matching);

    let confirmation = VerificationRequest {
        relying_party_id: request.rp_id.clone(),
        relying_party_name: None,
        action: VerificationAction::Authenticate,
    };
    let user_present = request.options.user_presence != Some(false);
    if user_present {
        match verification.request_confirmation(&confirmation, timeout) {
            Ok(VerificationDecision::Approved) => on_user_presence(),
            Ok(VerificationDecision::Rejected) => {
                return Ok(single_response(Ctap2Response::error(
                    Ctap2Status::OperationDenied,
                )));
            }
            Ok(VerificationDecision::Cancelled) => {
                return Ok(single_response(Ctap2Response::error(
                    Ctap2Status::KeepaliveCancel,
                )));
            }
            Err(error) if error.kind == PlatformErrorKind::Timeout => {
                return Ok(single_response(Ctap2Response::error(
                    Ctap2Status::UserActionTimeout,
                )));
            }
            Err(error) => return Err(error.into()),
        }
    }

    let number_of_credentials =
        (request.allow_list.is_none() && credential_count > 1).then_some(credential_count as u64);
    let response = sign_assertion_for_credential(
        request,
        &credential_id,
        store,
        key_store,
        number_of_credentials,
        user_verified,
        hmac_secret_shared_secret,
    )?;
    Ok(GetAssertionExecution {
        response,
        remaining_credentials,
    })
}

/// Signs the next credential in an already approved GetAssertion continuation.
pub fn execute_next_assertion(
    request: &GetAssertionRequest,
    credential_id: &CredentialId,
    store: &mut CredentialStore,
    key_store: &dyn KeyStore,
) -> Result<Ctap2Response, GetAssertionExecutionError> {
    execute_next_assertion_with_uv(request, credential_id, store, key_store, false)
}

pub fn execute_next_assertion_with_uv(
    request: &GetAssertionRequest,
    credential_id: &CredentialId,
    store: &mut CredentialStore,
    key_store: &dyn KeyStore,
    user_verified: bool,
) -> Result<Ctap2Response, GetAssertionExecutionError> {
    execute_next_assertion_with_uv_and_hmac_secret(
        request,
        credential_id,
        store,
        key_store,
        user_verified,
        None,
    )
}

pub fn execute_next_assertion_with_uv_and_hmac_secret(
    request: &GetAssertionRequest,
    credential_id: &CredentialId,
    store: &mut CredentialStore,
    key_store: &dyn KeyStore,
    user_verified: bool,
    hmac_secret_shared_secret: Option<&PinUvAuthSharedSecret>,
) -> Result<Ctap2Response, GetAssertionExecutionError> {
    sign_assertion_for_credential(
        request,
        credential_id,
        store,
        key_store,
        None,
        user_verified,
        hmac_secret_shared_secret,
    )
}

fn sign_assertion_for_credential(
    request: &GetAssertionRequest,
    credential_id: &CredentialId,
    store: &mut CredentialStore,
    key_store: &dyn KeyStore,
    number_of_credentials: Option<u64>,
    user_verified: bool,
    hmac_secret_shared_secret: Option<&PinUvAuthSharedSecret>,
) -> Result<Ctap2Response, GetAssertionExecutionError> {
    let id = [credential_id.as_bytes().to_vec()];
    let Some(record) = store
        .find_for_assertion(request.rp_id_hash(), Some(&id))
        .into_iter()
        .next()
    else {
        return Ok(Ctap2Response::error(Ctap2Status::NotAllowed));
    };
    let key_handle = record.key_handle.clone();
    let user_handle = record.user_handle.clone();
    let credential_hmac_secret = record.hmac_secret.clone();
    let credential_large_blob_key = if request.large_blob_key && record.discoverable {
        record.large_blob_key.as_ref()
    } else {
        None
    };
    let include_user = request.allow_list.is_none() && record.discoverable;
    let next_sign_count = record
        .sign_count
        .checked_add(1)
        .ok_or(CredentialError::CounterOverflow)?;
    let rp_id_hash = request.rp_id_hash();
    let reference = key_reference(&key_handle)?;
    let hmac_extensions = if let Some(input) = request.hmac_secret.as_ref() {
        let Some(shared_secret) = hmac_secret_shared_secret else {
            return Ok(Ctap2Response::error(Ctap2Status::PinAuthInvalid));
        };
        if shared_secret.protocol().id() as u64 != input.pin_uv_auth_protocol {
            return Ok(Ctap2Response::error(Ctap2Status::PinAuthInvalid));
        }
        if let Some(material) = credential_hmac_secret.as_ref() {
            let mut salt_enc = input.salt_enc.clone();
            let result = client_pin_process_hmac_secret_with_protocol(
                shared_secret,
                &mut salt_enc,
                &input.salt_auth,
                material.for_uv(user_verified),
            );
            let Ok(encrypted_output) = result else {
                return Ok(Ctap2Response::error(Ctap2Status::PinAuthInvalid));
            };
            Some(CborValue::Map(vec![(
                CborValue::Text("hmac-secret".into()),
                CborValue::Bytes(encrypted_output.to_vec()),
            )]))
        } else {
            if client_pin_validate_hmac_secret_request_with_protocol(
                shared_secret,
                &input.salt_enc,
                &input.salt_auth,
            )
            .is_err()
            {
                return Ok(Ctap2Response::error(Ctap2Status::PinAuthInvalid));
            }
            None
        }
    } else {
        None
    };
    let mut extension_values = match hmac_extensions {
        Some(CborValue::Map(values)) => values,
        None => Vec::new(),
        Some(_) => return Err(GetAssertionExecutionError::ResponseEncoding),
    };
    if request.get_cred_blob {
        extension_values.push((
            CborValue::Text("credBlob".into()),
            CborValue::Bytes(
                record
                    .cred_blob
                    .as_ref()
                    .map_or_else(Vec::new, |blob| blob.as_bytes().to_vec()),
            ),
        ));
    }
    let extensions =
        (!extension_values.is_empty()).then(|| Zeroizing::new(CborValue::Map(extension_values)));
    let response_extensions = extensions.as_ref().map(|value| (**value).clone());
    let user_present = request.options.user_presence != Some(false);
    let mut authenticator_data = Zeroizing::new(
        get_assertion_authenticator_data_with_presence_and_uv(
            rp_id_hash,
            next_sign_count,
            user_present,
            user_verified,
        )
        .to_vec(),
    );
    if let Some(ref extensions) = extensions {
        authenticator_data[32] |= 0x80;
        let encoded_extensions = Zeroizing::new(
            ghost_fido_core::encode_cbor(extensions)
                .map_err(|_| GetAssertionExecutionError::ResponseEncoding)?,
        );
        authenticator_data.extend_from_slice(&encoded_extensions);
    }
    let mut signed_data = Zeroizing::new(Vec::with_capacity(
        authenticator_data.len() + request.client_data_hash.len(),
    ));
    signed_data.extend_from_slice(&authenticator_data);
    signed_data.extend_from_slice(&request.client_data_hash);
    let digest = Sha256::digest(&signed_data);
    let raw_signature = key_store.sign(&reference, SigningAlgorithm::Es256, &digest)?;
    let signature = encode_p1363_es256_der(&raw_signature)
        .ok_or(GetAssertionExecutionError::InvalidSignature)?;

    let response = encode_get_assertion_response_with_count_and_presence_and_uv_and_extensions_and_large_blob_key(
        rp_id_hash,
        credential_id.as_bytes(),
        include_user.then_some(user_handle.as_slice()),
        &signature,
        next_sign_count,
        number_of_credentials,
        user_present,
        user_verified,
        response_extensions,
        credential_large_blob_key,
    )
    .map_err(|_| GetAssertionExecutionError::ResponseEncoding)?;
    let committed_sign_count = store.increment_sign_count(credential_id)?;
    if committed_sign_count != next_sign_count {
        return Err(GetAssertionExecutionError::Credential(
            CredentialError::StorageFailure,
        ));
    }
    Ok(response)
}

fn single_response(response: Ctap2Response) -> GetAssertionExecution {
    GetAssertionExecution {
        response,
        remaining_credentials: Vec::new(),
    }
}

fn key_reference(handle: &KeyHandle) -> Result<KeyReference, GetAssertionExecutionError> {
    let reference = std::str::from_utf8(handle.as_bytes())
        .map_err(|_| GetAssertionExecutionError::InvalidKeyReference)?;
    if reference.is_empty() {
        return Err(GetAssertionExecutionError::InvalidKeyReference);
    }
    Ok(KeyReference::new(reference))
}

fn encode_p1363_es256_der(signature: &[u8]) -> Option<Vec<u8>> {
    if signature.len() != 64 {
        return None;
    }
    let r = encode_der_integer(&signature[..32])?;
    let s = encode_der_integer(&signature[32..])?;
    let sequence_len = r.len() + s.len();
    let mut der = Vec::with_capacity(sequence_len + 2);
    der.push(0x30);
    der.push(u8::try_from(sequence_len).ok()?);
    der.extend_from_slice(&r);
    der.extend_from_slice(&s);
    Some(der)
}

fn encode_der_integer(scalar: &[u8]) -> Option<Vec<u8>> {
    let first_nonzero = scalar.iter().position(|byte| *byte != 0)?;
    let value = &scalar[first_nonzero..];
    let needs_positive_prefix = value[0] & 0x80 != 0;
    let length = value.len() + usize::from(needs_positive_prefix);
    let mut integer = Vec::with_capacity(length + 2);
    integer.push(0x02);
    integer.push(u8::try_from(length).ok()?);
    if needs_positive_prefix {
        integer.push(0);
    }
    integer.extend_from_slice(value);
    Some(integer)
}
