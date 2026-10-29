//! Single-credential CTAP2 GetAssertion execution.

use std::{cmp::Reverse, time::Duration};

use ghost_fido_core::{
    CredentialError, CredentialId, CredentialStore, Ctap2Response, Ctap2Status,
    GetAssertionRequest, KeyHandle, encode_get_assertion_response_with_count,
    get_assertion_authenticator_data,
};
use sha2::{Digest, Sha256};

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
    if request.options.user_verification == Some(true)
        || request.options.user_presence == Some(false)
    {
        return Ok(single_response(Ctap2Response::error(
            Ctap2Status::UnsupportedOption,
        )));
    }

    let mut matching = request.find_credentials(store);
    if matching.is_empty() {
        return Ok(single_response(Ctap2Response::error(
            Ctap2Status::NoCredentials,
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
    match verification.request_confirmation(&confirmation, timeout) {
        Ok(VerificationDecision::Approved) => {}
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

    let number_of_credentials =
        (request.allow_list.is_none() && credential_count > 1).then_some(credential_count as u64);
    let response = sign_assertion_for_credential(
        request,
        &credential_id,
        store,
        key_store,
        number_of_credentials,
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
    sign_assertion_for_credential(request, credential_id, store, key_store, None)
}

fn sign_assertion_for_credential(
    request: &GetAssertionRequest,
    credential_id: &CredentialId,
    store: &mut CredentialStore,
    key_store: &dyn KeyStore,
    number_of_credentials: Option<u64>,
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
    let include_user = request.allow_list.is_none() && record.discoverable;
    let next_sign_count = record
        .sign_count
        .checked_add(1)
        .ok_or(CredentialError::CounterOverflow)?;
    let rp_id_hash = request.rp_id_hash();
    let reference = key_reference(&key_handle)?;
    let authenticator_data = get_assertion_authenticator_data(rp_id_hash, next_sign_count);
    let mut signed_data =
        Vec::with_capacity(authenticator_data.len() + request.client_data_hash.len());
    signed_data.extend_from_slice(&authenticator_data);
    signed_data.extend_from_slice(&request.client_data_hash);
    let digest = Sha256::digest(&signed_data);
    let raw_signature = key_store.sign(&reference, SigningAlgorithm::Es256, &digest)?;
    let signature = encode_p1363_es256_der(&raw_signature)
        .ok_or(GetAssertionExecutionError::InvalidSignature)?;

    let response = encode_get_assertion_response_with_count(
        rp_id_hash,
        credential_id.as_bytes(),
        include_user.then_some(user_handle.as_slice()),
        &signature,
        next_sign_count,
        number_of_credentials,
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
