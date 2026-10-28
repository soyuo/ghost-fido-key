//! Single-credential CTAP2 GetAssertion execution.

use std::time::Duration;

use ghost_fido_core::{
    CredentialError, CredentialStore, Ctap2Response, Ctap2Status, GetAssertionRequest, KeyHandle,
    encode_get_assertion_response, get_assertion_authenticator_data,
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

/// Approves and signs a GetAssertion request when exactly one credential matches.
pub fn execute_get_assertion(
    request: &GetAssertionRequest,
    store: &mut CredentialStore,
    key_store: &dyn KeyStore,
    verification: &dyn UserVerification,
    timeout: Duration,
) -> Result<Ctap2Response, GetAssertionExecutionError> {
    if request.options.user_verification == Some(true)
        || request.options.user_presence == Some(false)
    {
        return Ok(protocol_error(Ctap2Status::UnsupportedOption));
    }

    let matching = request.find_credentials(store);
    if matching.is_empty() {
        return Ok(protocol_error(Ctap2Status::NoCredentials));
    }
    if matching.len() != 1 {
        return Ok(protocol_error(Ctap2Status::OperationDenied));
    }

    let record = matching[0];
    let credential_id = record.id.clone();
    let key_handle = record.key_handle.clone();
    let user_handle = record.user_handle.clone();
    let include_user = request.allow_list.is_none() && record.discoverable;
    let next_sign_count = record
        .sign_count
        .checked_add(1)
        .ok_or(CredentialError::CounterOverflow)?;
    let rp_id_hash = request.rp_id_hash();
    drop(matching);

    let confirmation = VerificationRequest {
        relying_party_id: request.rp_id.clone(),
        relying_party_name: None,
        action: VerificationAction::Authenticate,
    };
    match verification.request_confirmation(&confirmation, timeout) {
        Ok(VerificationDecision::Approved) => {}
        Ok(VerificationDecision::Rejected) => {
            return Ok(protocol_error(Ctap2Status::OperationDenied));
        }
        Err(error) if error.kind == PlatformErrorKind::Timeout => {
            return Ok(protocol_error(Ctap2Status::UserActionTimeout));
        }
        Err(error) => return Err(error.into()),
    }

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

    let response = encode_get_assertion_response(
        rp_id_hash,
        credential_id.as_bytes(),
        include_user.then_some(user_handle.as_slice()),
        &signature,
        next_sign_count,
    )
    .map_err(|_| GetAssertionExecutionError::ResponseEncoding)?;
    let committed_sign_count = store.increment_sign_count(&credential_id)?;
    if committed_sign_count != next_sign_count {
        return Err(GetAssertionExecutionError::Credential(
            CredentialError::StorageFailure,
        ));
    }
    Ok(response)
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

fn protocol_error(status: Ctap2Status) -> Ctap2Response {
    Ctap2Response {
        status,
        payload: Vec::new(),
    }
}
