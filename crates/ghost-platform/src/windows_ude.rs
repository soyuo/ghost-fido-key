//! Windows UDE user-mode boundary.
//!
//! The actual UdeCx/KMDF implementation lives under `platforms/windows/ude`.
//! This Rust adapter intentionally fails closed until a signed driver exposes
//! the documented control endpoint and IOCTL contract.

use std::{
    fs::OpenOptions,
    io,
    path::{Path, PathBuf},
    time::Duration,
};

use crate::{
    CapabilityState, CapabilityStatus, DeviceState, HostPlatform, PlatformCapabilities,
    PlatformError, PlatformErrorKind, VirtualHidBackend,
};

/// User-mode control endpoint reserved by the native UDE driver.
pub const DEFAULT_UDE_CONTROL_PATH: &str = r"\\.\GhostFidoUde";

/// Windows status provider for the native UDE boundary.
pub struct WindowsUdeBackend {
    control_path: PathBuf,
    state: DeviceState,
}

impl WindowsUdeBackend {
    #[must_use]
    pub fn new() -> Self {
        Self::with_control_path(DEFAULT_UDE_CONTROL_PATH)
    }

    #[must_use]
    pub fn with_control_path(path: impl AsRef<Path>) -> Self {
        Self {
            control_path: path.as_ref().to_path_buf(),
            state: DeviceState::Detached,
        }
    }

    #[must_use]
    pub fn control_path(&self) -> &Path {
        &self.control_path
    }

    #[must_use]
    pub fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities {
            virtual_hid: self.availability(),
            protected_key_storage: CapabilityStatus::unavailable(
                CapabilityState::NotImplemented,
                "Windows protected key provider is not implemented",
            ),
            user_verification: CapabilityStatus::unavailable(
                CapabilityState::NotImplemented,
                "Windows user verification provider is not implemented",
            ),
        }
    }

    fn error(kind: PlatformErrorKind, detail: impl Into<String>) -> PlatformError {
        PlatformError::new(kind, HostPlatform::Windows, detail)
    }
}

impl Default for WindowsUdeBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualHidBackend for WindowsUdeBackend {
    fn availability(&self) -> CapabilityStatus {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.control_path)
        {
            Ok(_) => CapabilityStatus::unavailable(
                CapabilityState::NotImplemented,
                "UDE control endpoint exists; signed IOCTL readiness handshake is not implemented",
            ),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                CapabilityStatus::unavailable(
                    CapabilityState::PermissionRequired,
                    format!(
                        "{} requires driver access permission",
                        self.control_path.display()
                    ),
                )
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => CapabilityStatus::unavailable(
                CapabilityState::DriverMissing,
                format!(
                    "UDE control endpoint {} is missing",
                    self.control_path.display()
                ),
            ),
            Err(error) => CapabilityStatus::unavailable(
                CapabilityState::Error,
                format!("failed to inspect UDE control endpoint: {error}"),
            ),
        }
    }

    fn attach(&mut self) -> Result<(), PlatformError> {
        self.state = DeviceState::Failed;
        Err(Self::error(
            PlatformErrorKind::NotImplemented,
            "UDE attach IOCTL contract is not implemented",
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
            "UDE report IOCTL contract is not implemented",
        ))
    }

    fn receive_output_report(&mut self, _timeout: Duration) -> Result<Vec<u8>, PlatformError> {
        Err(Self::error(
            PlatformErrorKind::NotImplemented,
            "UDE report IOCTL contract is not implemented",
        ))
    }
}
