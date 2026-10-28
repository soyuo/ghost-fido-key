//! Windows CNG key storage boundary.
//!
//! CNG calls are kept behind this provider. Until persisted-key creation and
//! the signing ABI are wired and validated on Windows, this implementation
//! fails closed instead of reporting a software key as protected.

use crate::{
    HostPlatform, KeyCreationPolicy, KeyMetadata, KeyProtection, KeyReference, KeyStore,
    PlatformError, PlatformErrorKind, SigningAlgorithm,
};

#[derive(Debug, Default)]
pub struct WindowsKeyStore;

impl WindowsKeyStore {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub const fn preferred_provider() -> &'static str {
        "Microsoft Platform Crypto Provider"
    }
}

impl KeyStore for WindowsKeyStore {
    fn create_signing_key(
        &self,
        _algorithm: SigningAlgorithm,
        policy: KeyCreationPolicy,
    ) -> Result<(KeyReference, KeyMetadata), PlatformError> {
        let detail = match policy {
            KeyCreationPolicy::PlatformProtectedOnly => {
                "Windows CNG protected key creation is not available in this build"
            }
            KeyCreationPolicy::SoftwareKeyAfterExplicitConsent => {
                "software key creation requires the separately reviewed consent provider"
            }
        };
        Err(PlatformError::new(
            PlatformErrorKind::KeyStoreUnavailable,
            HostPlatform::Windows,
            detail,
        ))
    }

    fn sign(
        &self,
        _key: &KeyReference,
        _algorithm: SigningAlgorithm,
        _message: &[u8],
    ) -> Result<Vec<u8>, PlatformError> {
        Err(PlatformError::new(
            PlatformErrorKind::KeyStoreUnavailable,
            HostPlatform::Windows,
            "Windows CNG signing is not available in this build",
        ))
    }

    fn delete_key(&self, _key: &KeyReference) -> Result<(), PlatformError> {
        Err(PlatformError::new(
            PlatformErrorKind::KeyStoreUnavailable,
            HostPlatform::Windows,
            "Windows CNG key deletion is not available in this build",
        ))
    }
}

const _: Option<KeyProtection> = None;
