//! Shared contracts for operating-system services used by the authenticator.
//!
//! This crate contains no native API calls. Platform adapters implement these
//! traits and report observed capabilities instead of inferring them from the
//! host operating-system name.

use ghost_fido_core::Es256PublicKey;
use std::{fmt, time::Duration};

#[cfg(target_os = "linux")]
mod linux_uhid;

#[cfg(target_os = "linux")]
mod linux_credential_protector;

#[cfg(target_os = "linux")]
mod linux_keystore;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod credential_protector;

mod assertion;
mod authenticator;
mod ctaphid_service;
mod registration;

#[cfg(target_os = "linux")]
pub use linux_uhid::LinuxUhidBackend;

#[cfg(target_os = "linux")]
pub use linux_credential_protector::LinuxCredentialProtector;

#[cfg(target_os = "linux")]
pub use linux_keystore::LinuxKeyStore;

pub use assertion::{
    GetAssertionExecution, GetAssertionExecutionError, execute_get_assertion,
    execute_get_assertion_with_uv, execute_get_assertion_with_uv_and_hmac_secret,
    execute_next_assertion, execute_next_assertion_with_uv,
    execute_next_assertion_with_uv_and_hmac_secret,
};
pub use authenticator::{
    AuthenticatorService, AuthenticatorServiceConfig, AuthenticatorServiceError,
};
pub use ctaphid_service::AuthenticatorHidSession;
pub use registration::{
    MakeCredentialExecutionError, check_credential_exclusion, register_make_credential,
    register_make_credential_with_uv,
};

#[cfg(target_os = "windows")]
mod windows_ude;

#[cfg(target_os = "windows")]
pub use windows_ude::WindowsUdeBackend;

#[cfg(target_os = "windows")]
mod windows_keystore;

#[cfg(target_os = "windows")]
pub use windows_keystore::WindowsKeyStore;

#[cfg(target_os = "windows")]
mod windows_dpapi;

#[cfg(target_os = "windows")]
pub use windows_dpapi::WindowsCredentialProtector;

#[cfg(target_os = "macos")]
mod macos_corehid;
#[cfg(target_os = "macos")]
mod macos_corehid_ffi;

#[cfg(target_os = "macos")]
pub use macos_corehid::MacOsCoreHidBackend;

#[cfg(target_os = "macos")]
mod macos_keystore;

#[cfg(target_os = "macos")]
mod macos_credential_protector;

#[cfg(target_os = "macos")]
pub use macos_keystore::MacOsKeyStore;

#[cfg(target_os = "macos")]
pub use macos_credential_protector::MacOsCredentialProtector;

/// Host operating system selected at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPlatform {
    Windows,
    MacOs,
    Linux,
    Other,
}

impl HostPlatform {
    /// Identifies the target selected by Rust's target configuration.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else {
            Self::Other
        }
    }
}

/// Result of checking one platform feature at runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityStatus {
    pub state: CapabilityState,
    /// A diagnostic suitable for logs or a user-facing explanation.
    pub detail: Option<String>,
}

impl CapabilityStatus {
    #[must_use]
    pub const fn available() -> Self {
        Self {
            state: CapabilityState::Available,
            detail: None,
        }
    }

    #[must_use]
    pub fn unavailable(state: CapabilityState, detail: impl Into<String>) -> Self {
        Self {
            state,
            detail: Some(detail.into()),
        }
    }

    /// Configuration is sufficient to attempt startup, but runtime support
    /// has not been validated.
    #[must_use]
    pub fn configured(detail: impl Into<String>) -> Self {
        Self {
            state: CapabilityState::Configured,
            detail: Some(detail.into()),
        }
    }

    /// The provider implementation exists; runtime readiness is checked when
    /// the provider is used.
    #[must_use]
    pub fn implemented(detail: impl Into<String>) -> Self {
        Self {
            state: CapabilityState::Implemented,
            detail: Some(detail.into()),
        }
    }

    /// Whether prerequisites are sufficient to attempt starting the backend.
    /// `Configured` permits a runtime attempt but does not prove transport or
    /// browser interoperability.
    #[must_use]
    pub const fn can_start(&self) -> bool {
        matches!(
            self.state,
            CapabilityState::Available | CapabilityState::Configured
        )
    }
}

/// Why a platform capability can or cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityState {
    Available,
    /// Configuration is complete enough to attempt startup, but runtime
    /// transport validation has not established availability.
    Configured,
    /// The provider implementation exists, but runtime readiness has not been
    /// checked. This state does not mean that the provider is available.
    Implemented,
    PermissionRequired,
    DriverMissing,
    EntitlementUnavailable,
    Unsupported,
    NotImplemented,
    Error,
}

/// Runtime capabilities reported by an OS adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformCapabilities {
    pub virtual_hid: CapabilityStatus,
    pub protected_key_storage: CapabilityStatus,
    pub user_verification: CapabilityStatus,
}

/// Virtual authenticator attachment lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    Detached,
    Starting,
    Attached,
    Stopping,
    Failed,
}

/// Stable categories for platform errors, with the diagnostic retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformErrorKind {
    NotImplemented,
    PermissionDenied,
    DriverMissing,
    EntitlementUnavailable,
    Unsupported,
    Io,
    Timeout,
    InvalidReport,
    KeyStoreUnavailable,
    PlatformKeyProtectionUnavailable,
    UserVerificationUnavailable,
    UserRejected,
}

/// Error returned from a platform provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformError {
    pub kind: PlatformErrorKind,
    pub platform: HostPlatform,
    pub detail: String,
}

impl PlatformError {
    #[must_use]
    pub fn new(kind: PlatformErrorKind, platform: HostPlatform, detail: impl Into<String>) -> Self {
        Self {
            kind,
            platform,
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn not_implemented(platform: HostPlatform, feature: &str) -> Self {
        Self::new(
            PlatformErrorKind::NotImplemented,
            platform,
            format!("{feature} is not implemented for {platform:?}"),
        )
    }
}

impl fmt::Display for PlatformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:?} on {:?}: {}",
            self.kind, self.platform, self.detail
        )
    }
}

impl std::error::Error for PlatformError {}

/// Contract implemented by each operating-system virtual HID adapter.
pub trait VirtualHidBackend: Send {
    /// Reports observed availability, including actionable failure details.
    fn availability(&self) -> CapabilityStatus;

    /// Convenience check for callers that only need a yes/no answer.
    fn is_available(&self) -> bool {
        self.availability().state == CapabilityState::Available
    }

    /// Creates and attaches the virtual FIDO HID device.
    fn attach(&mut self) -> Result<(), PlatformError>;

    /// Detaches the virtual device. Detach should be safe to call repeatedly.
    fn detach(&mut self) -> Result<(), PlatformError>;

    /// Returns the current attachment state.
    fn state(&self) -> DeviceState;

    /// Sends one HID input report from the authenticator to the host.
    fn send_input_report(&mut self, report: &[u8]) -> Result<(), PlatformError>;

    /// Receives one HID output report from the host, waiting no longer than `timeout`.
    fn receive_output_report(&mut self, timeout: Duration) -> Result<Vec<u8>, PlatformError>;
}

/// Construct the virtual HID adapter selected for the current target.
///
/// Each implementation reports observed readiness and fails closed until its
/// native transport is ready. Unsupported targets receive the unavailable
/// placeholder rather than an adapter inferred from their operating system.
#[must_use]
pub fn host_virtual_hid_backend() -> Box<dyn VirtualHidBackend> {
    #[cfg(target_os = "linux")]
    {
        return Box::new(LinuxUhidBackend::new());
    }

    #[cfg(target_os = "windows")]
    {
        return Box::new(WindowsUdeBackend::new());
    }

    #[cfg(target_os = "macos")]
    {
        return Box::new(MacOsCoreHidBackend::new());
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        Box::new(UnavailableBackend)
    }
}

/// Cryptographic algorithm supported by the first FIDO credential profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// ECDSA over P-256 with SHA-256 (COSE algorithm -7).
    Es256,
}

/// Protection provided for a generated private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProtection {
    HardwareBacked,
    OsProtected,
    Software,
}

/// Non-secret properties of a key stored by a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyMetadata {
    pub protection: KeyProtection,
    pub exportable: bool,
}

/// Opaque private-key reference and non-secret public material from key creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedSigningKey {
    pub reference: KeyReference,
    pub metadata: KeyMetadata,
    pub public_key: Es256PublicKey,
}

/// Selects whether creation of a software-protected key was explicitly approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCreationPolicy {
    PlatformProtectedOnly,
    /// Use this only after the user has accepted an explicit security warning.
    SoftwareKeyAfterExplicitConsent,
}

/// One-time proof that a user accepted the software-key security warning.
/// The value cannot be constructed by platform code without calling `confirm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoftwareKeyConsent(ConsentMarker);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsentMarker {
    ExplicitlyAccepted,
}

impl SoftwareKeyConsent {
    /// Create consent after the native approval flow confirms user acceptance.
    #[must_use]
    pub const fn confirm_user_acceptance(accepted: bool) -> Option<Self> {
        if accepted {
            Some(Self(ConsentMarker::ExplicitlyAccepted))
        } else {
            None
        }
    }
}

/// Opaque identifier for a key held by a provider. It never contains key bytes.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct KeyReference(String);

impl KeyReference {
    #[must_use]
    pub fn new(provider_reference: impl Into<String>) -> Self {
        Self(provider_reference.into())
    }

    #[must_use]
    pub fn as_provider_reference(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for KeyReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyReference([REDACTED])")
    }
}

/// Platform key storage contract. Implementations return public material and
/// signatures, never private key material.
pub trait KeyStore: Send + Sync {
    fn allocate_signing_key_reference(
        &self,
        policy: KeyCreationPolicy,
        consent: Option<SoftwareKeyConsent>,
    ) -> Result<KeyReference, PlatformError>;

    fn create_signing_key(
        &self,
        reference: &KeyReference,
        algorithm: SigningAlgorithm,
        policy: KeyCreationPolicy,
        consent: Option<SoftwareKeyConsent>,
    ) -> Result<CreatedSigningKey, PlatformError>;

    /// Signs a precomputed digest. For ES256, the input is a 32-byte SHA-256
    /// digest and the result must be the fixed-width IEEE P1363 `r || s` form
    /// (32-byte big-endian scalar each). Protocol adapters encode it as DER.
    fn sign(
        &self,
        key: &KeyReference,
        algorithm: SigningAlgorithm,
        digest: &[u8],
    ) -> Result<Vec<u8>, PlatformError>;

    /// Returns public ES256 coordinates for a persisted credential key.
    /// Implementations must never expose private key material.
    fn public_key(
        &self,
        key: &KeyReference,
    ) -> Result<ghost_fido_core::Es256PublicKey, PlatformError>;

    fn delete_key(&self, key: &KeyReference) -> Result<(), PlatformError>;
}

/// User-visible action that requires local confirmation before signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationAction {
    RegisterCredential,
    SoftwareKeyFallback,
    Authenticate,
    CredentialExclusionCheck,
    SelectAuthenticator,
    ResetAuthenticator,
}

/// Minimum RP context presented to the local user for an approval request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationRequest {
    pub relying_party_id: String,
    pub relying_party_name: Option<String>,
    pub action: VerificationAction,
}

/// Result of an explicit local confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationDecision {
    Approved,
    Rejected,
    Cancelled,
}

/// Local user-presence or verification provider.
pub trait UserVerification: Send + Sync {
    fn request_confirmation(
        &self,
        request: &VerificationRequest,
        timeout: Duration,
    ) -> Result<VerificationDecision, PlatformError>;

    /// Cancels the active user-presence request, if one is waiting.
    fn cancel_pending(&self) {}
}

/// Application lifecycle hooks for safely detaching platform resources.
pub trait PlatformLifecycle: Send + Sync {
    /// Release temporary handles and detach active virtual devices during shutdown.
    fn shutdown(&self) -> Result<(), PlatformError>;
}

/// Placeholder provider that fails closed until native adapters are implemented.
#[derive(Debug, Default)]
pub struct UnavailableBackend;

impl UnavailableBackend {
    #[must_use]
    pub fn capabilities(&self) -> PlatformCapabilities {
        let not_implemented = |feature: &str| {
            CapabilityStatus::unavailable(
                CapabilityState::NotImplemented,
                format!(
                    "{feature} is not implemented for {:?}",
                    HostPlatform::current()
                ),
            )
        };

        PlatformCapabilities {
            virtual_hid: self.availability(),
            protected_key_storage: not_implemented("protected key storage"),
            user_verification: not_implemented("user verification"),
        }
    }
}

impl VirtualHidBackend for UnavailableBackend {
    fn availability(&self) -> CapabilityStatus {
        CapabilityStatus::unavailable(
            CapabilityState::NotImplemented,
            format!(
                "virtual FIDO HID is not implemented for {:?}",
                HostPlatform::current()
            ),
        )
    }

    fn attach(&mut self) -> Result<(), PlatformError> {
        Err(PlatformError::not_implemented(
            HostPlatform::current(),
            "virtual FIDO HID",
        ))
    }

    fn detach(&mut self) -> Result<(), PlatformError> {
        Ok(())
    }

    fn state(&self) -> DeviceState {
        DeviceState::Detached
    }

    fn send_input_report(&mut self, _report: &[u8]) -> Result<(), PlatformError> {
        Err(PlatformError::not_implemented(
            HostPlatform::current(),
            "HID input reports",
        ))
    }

    fn receive_output_report(&mut self, _timeout: Duration) -> Result<Vec<u8>, PlatformError> {
        Err(PlatformError::not_implemented(
            HostPlatform::current(),
            "HID output reports",
        ))
    }
}

impl KeyStore for UnavailableBackend {
    fn allocate_signing_key_reference(
        &self,
        _policy: KeyCreationPolicy,
        _consent: Option<SoftwareKeyConsent>,
    ) -> Result<KeyReference, PlatformError> {
        Err(PlatformError::new(
            PlatformErrorKind::KeyStoreUnavailable,
            HostPlatform::current(),
            "protected key storage is not implemented",
        ))
    }

    fn create_signing_key(
        &self,
        _reference: &KeyReference,
        _algorithm: SigningAlgorithm,
        _policy: KeyCreationPolicy,
        _consent: Option<SoftwareKeyConsent>,
    ) -> Result<CreatedSigningKey, PlatformError> {
        Err(PlatformError::new(
            PlatformErrorKind::KeyStoreUnavailable,
            HostPlatform::current(),
            "protected key storage is not implemented",
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
            HostPlatform::current(),
            "signing is unavailable because key storage is not implemented",
        ))
    }

    fn delete_key(&self, _key: &KeyReference) -> Result<(), PlatformError> {
        Err(PlatformError::new(
            PlatformErrorKind::KeyStoreUnavailable,
            HostPlatform::current(),
            "key deletion is unavailable because key storage is not implemented",
        ))
    }

    fn public_key(
        &self,
        _key: &KeyReference,
    ) -> Result<ghost_fido_core::Es256PublicKey, PlatformError> {
        Err(PlatformError::new(
            PlatformErrorKind::KeyStoreUnavailable,
            HostPlatform::current(),
            "public-key retrieval is unavailable because key storage is not implemented",
        ))
    }
}

impl UserVerification for UnavailableBackend {
    fn request_confirmation(
        &self,
        _request: &VerificationRequest,
        _timeout: Duration,
    ) -> Result<VerificationDecision, PlatformError> {
        Err(PlatformError::new(
            PlatformErrorKind::UserVerificationUnavailable,
            HostPlatform::current(),
            "local user verification is not implemented",
        ))
    }
}

impl PlatformLifecycle for UnavailableBackend {
    fn shutdown(&self) -> Result<(), PlatformError> {
        Ok(())
    }
}
