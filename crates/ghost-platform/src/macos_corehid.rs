//! macOS CoreHID user-mode boundary.
//!
//! CoreHID and its entitlement are implemented in the Swift layer under
//! `platforms/macos/corehid`. Rust reports the boundary as unavailable until
//! that signed native bridge proves entitlement and readiness.

use std::time::Duration;

use crate::{
    CapabilityState, CapabilityStatus, DeviceState, HostPlatform, PlatformCapabilities,
    PlatformError, PlatformErrorKind, VirtualHidBackend,
};

/// macOS CoreHID status provider. `entitlement_granted` is supplied by a
/// future signed Swift bridge; it is false by default and never inferred.
pub struct MacOsCoreHidBackend {
    entitlement_granted: bool,
    state: DeviceState,
}

impl MacOsCoreHidBackend {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entitlement_granted: false,
            state: DeviceState::Detached,
        }
    }

    #[must_use]
    pub const fn with_entitlement_status(entitlement_granted: bool) -> Self {
        Self {
            entitlement_granted,
            state: DeviceState::Detached,
        }
    }

    #[must_use]
    pub const fn entitlement_granted(&self) -> bool {
        self.entitlement_granted
    }

    #[must_use]
    pub fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities {
            virtual_hid: self.availability(),
            protected_key_storage: CapabilityStatus::unavailable(
                CapabilityState::NotImplemented,
                "macOS protected key provider is not implemented",
            ),
            user_verification: CapabilityStatus::unavailable(
                CapabilityState::NotImplemented,
                "macOS user verification provider is not implemented",
            ),
        }
    }

    fn error(kind: PlatformErrorKind, detail: impl Into<String>) -> PlatformError {
        PlatformError::new(kind, HostPlatform::MacOs, detail)
    }
}

impl Default for MacOsCoreHidBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualHidBackend for MacOsCoreHidBackend {
    fn availability(&self) -> CapabilityStatus {
        if !self.entitlement_granted {
            return CapabilityStatus::unavailable(
                CapabilityState::EntitlementUnavailable,
                "com.apple.developer.hid.virtual.device is not confirmed",
            );
        }

        CapabilityStatus::unavailable(
            CapabilityState::NotImplemented,
            "CoreHID signed bridge readiness is not implemented",
        )
    }

    fn attach(&mut self) -> Result<(), PlatformError> {
        self.state = DeviceState::Failed;
        let kind = if self.entitlement_granted {
            PlatformErrorKind::NotImplemented
        } else {
            PlatformErrorKind::EntitlementUnavailable
        };
        Err(Self::error(
            kind,
            "CoreHID virtual-device attach is unavailable",
        ))
    }

    fn detach(&mut self) -> Result<(), PlatformError> {
        self.state = DeviceState::Detached;
        Ok(())
    }

    fn state(&self) -> DeviceState {
        self.state
    }

    fn send_input_report(&mut self, _report: &[u8]) -> Result<(), PlatformError> {
        Err(Self::error(
            PlatformErrorKind::NotImplemented,
            "CoreHID report bridge is not implemented",
        ))
    }

    fn receive_output_report(&mut self, _timeout: Duration) -> Result<Vec<u8>, PlatformError> {
        Err(Self::error(
            PlatformErrorKind::NotImplemented,
            "CoreHID report bridge is not implemented",
        ))
    }
}
