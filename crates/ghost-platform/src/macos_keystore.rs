//! macOS protected-key provider boundary.
//!
//! Security.framework operations will be provided through the signed Swift
//! bridge. Until the bridge is linked and its actual key attributes are
//! available, this provider reports no key capability and fails closed.

use crate::{
    CreatedSigningKey, HostPlatform, KeyCreationPolicy, KeyStore, PlatformError, PlatformErrorKind,
    SigningAlgorithm, SoftwareKeyConsent,
};

#[derive(Debug, Default)]
pub struct MacOsKeyStore;

impl MacOsKeyStore {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl KeyStore for MacOsKeyStore {
    fn create_signing_key(
        &self,
        _algorithm: SigningAlgorithm,
        _policy: KeyCreationPolicy,
        _consent: Option<SoftwareKeyConsent>,
    ) -> Result<CreatedSigningKey, PlatformError> {
        Err(PlatformError::new(
            PlatformErrorKind::KeyStoreUnavailable,
            HostPlatform::MacOs,
            "Security.framework bridge is not linked; no key was created",
        ))
    }

    fn sign(
        &self,
        _key: &KeyReference,
        _algorithm: SigningAlgorithm,
        _digest: &[u8],
    ) -> Result<Vec<u8>, PlatformError> {
        Err(PlatformError::new(
            PlatformErrorKind::KeyStoreUnavailable,
            HostPlatform::MacOs,
            "Security.framework signing is unavailable",
        ))
    }

    fn delete_key(&self, _key: &KeyReference) -> Result<(), PlatformError> {
        Err(PlatformError::new(
            PlatformErrorKind::KeyStoreUnavailable,
            HostPlatform::MacOs,
            "Security.framework key deletion is unavailable",
        ))
    }
}
