//! Platform-independent MakeCredential checks that require local presence.

use ghost_fido_core::{CredentialStore, Ctap2Response, Ctap2Status, MakeCredentialRequest};
use std::time::Duration;

use crate::{
    PlatformError, PlatformErrorKind, UserVerification, VerificationAction, VerificationDecision,
    VerificationRequest,
};

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
        Err(error) if error.kind == PlatformErrorKind::Timeout => {}
        Err(error) => return Err(error),
    }

    Ok(Some(Ctap2Response {
        status: Ctap2Status::CredentialExcluded,
        payload: Vec::new(),
    }))
}
