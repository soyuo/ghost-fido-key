//! macOS CoreHID virtual HID backend.

use std::time::Duration;

use crate::{
    CapabilityState, CapabilityStatus, DeviceState, HostPlatform, PlatformCapabilities,
    PlatformError, PlatformErrorKind, VirtualHidBackend,
    macos_corehid_ffi::{BridgeError, CoreHIDHandle},
};

#[derive(Debug, Clone, Copy)]
struct ProductIdentity {
    vendor_id: u16,
    product_id: u16,
}

impl ProductIdentity {
    fn from_build_configuration() -> Option<Self> {
        let vendor_id = option_env!("GHOST_FIDO_MACOS_VENDOR_ID")?.parse().ok()?;
        let product_id = option_env!("GHOST_FIDO_MACOS_PRODUCT_ID")?.parse().ok()?;
        (vendor_id != 0 && product_id != 0).then_some(Self {
            vendor_id,
            product_id,
        })
    }
}

/// Rust owner of the Swift CoreHID bridge. Product identity is compiled in
/// only when both assigned IDs are explicitly provided to the build.
pub struct MacOsCoreHidBackend {
    identity: Option<ProductIdentity>,
    native: Option<CoreHIDHandle>,
    state: DeviceState,
}

impl MacOsCoreHidBackend {
    #[must_use]
    pub fn new() -> Self {
        Self {
            identity: ProductIdentity::from_build_configuration(),
            native: None,
            state: DeviceState::Detached,
        }
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

    fn bridge_error(error: BridgeError, operation: &str) -> PlatformError {
        let (kind, detail) = match error {
            BridgeError::InvalidArgument => (
                PlatformErrorKind::InvalidReport,
                format!("CoreHID {operation} rejected an invalid argument"),
            ),
            BridgeError::NotPermitted => (
                PlatformErrorKind::EntitlementUnavailable,
                format!(
                    "CoreHID {operation} requires the signed com.apple.developer.hid.virtual.device entitlement"
                ),
            ),
            BridgeError::TimedOut => (
                PlatformErrorKind::Timeout,
                format!("CoreHID {operation} timed out"),
            ),
            BridgeError::NotReady => (
                PlatformErrorKind::Unsupported,
                format!("CoreHID {operation} is unavailable on this macOS version"),
            ),
            BridgeError::NoResources => (
                PlatformErrorKind::Io,
                format!("CoreHID {operation} could not allocate the virtual device"),
            ),
            BridgeError::Io => (PlatformErrorKind::Io, format!("CoreHID {operation} failed")),
        };
        Self::error(kind, detail)
    }
}

impl Default for MacOsCoreHidBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualHidBackend for MacOsCoreHidBackend {
    fn availability(&self) -> CapabilityStatus {
        if self.native.is_some() {
            return CapabilityStatus::available();
        }

        let Some(identity) = self.identity else {
            return CapabilityStatus::unavailable(
                CapabilityState::NotImplemented,
                "assigned macOS virtual HID vendor and product IDs are not configured",
            );
        };

        match super::macos_corehid_ffi::check_readiness(identity.vendor_id, identity.product_id) {
            Ok(()) => CapabilityStatus::available(),
            Err(BridgeError::NotPermitted) => CapabilityStatus::unavailable(
                CapabilityState::EntitlementUnavailable,
                "the signed app does not contain Apple's virtual HID entitlement",
            ),
            Err(BridgeError::NotReady) => CapabilityStatus::unavailable(
                CapabilityState::Unsupported,
                "CoreHID virtual devices require macOS 15 or later",
            ),
            Err(error) => CapabilityStatus::unavailable(
                CapabilityState::Error,
                Self::bridge_error(error, "readiness check").detail,
            ),
        }
    }

    fn attach(&mut self) -> Result<(), PlatformError> {
        if self.native.is_some() {
            self.state = DeviceState::Attached;
            return Ok(());
        }
        self.state = DeviceState::Starting;
        let Some(identity) = self.identity else {
            self.state = DeviceState::Failed;
            return Err(Self::error(
                PlatformErrorKind::NotImplemented,
                "assigned macOS virtual HID vendor and product IDs are not configured",
            ));
        };

        match CoreHIDHandle::create(identity.vendor_id, identity.product_id) {
            Ok(native) => {
                self.native = Some(native);
                self.state = DeviceState::Attached;
                Ok(())
            }
            Err(error) => {
                self.state = DeviceState::Failed;
                Err(Self::bridge_error(error, "device activation"))
            }
        }
    }

    fn detach(&mut self) -> Result<(), PlatformError> {
        self.state = DeviceState::Stopping;
        let result = self
            .native
            .take()
            .map(|mut native| native.destroy())
            .transpose()
            .map_err(|error| Self::bridge_error(error, "device deactivation"));
        self.state = DeviceState::Detached;
        result.map(|_| ())
    }

    fn state(&self) -> DeviceState {
        self.state
    }

    fn send_input_report(&mut self, report: &[u8]) -> Result<(), PlatformError> {
        if report.len() != 64 {
            return Err(Self::error(
                PlatformErrorKind::InvalidReport,
                format!(
                    "CoreHID input report must be 64 bytes, got {}",
                    report.len()
                ),
            ));
        }
        let native = self.native.as_ref().ok_or_else(|| {
            Self::error(
                PlatformErrorKind::Unsupported,
                "CoreHID virtual device is not attached",
            )
        })?;
        native
            .send_input_report(report)
            .map_err(|error| Self::bridge_error(error, "input report dispatch"))
    }

    fn receive_output_report(&mut self, timeout: Duration) -> Result<Vec<u8>, PlatformError> {
        let native = self.native.as_ref().ok_or_else(|| {
            Self::error(
                PlatformErrorKind::Unsupported,
                "CoreHID virtual device is not attached",
            )
        })?;
        native
            .receive_output_report(timeout)
            .map_err(|error| Self::bridge_error(error, "output report receive"))
    }
}
