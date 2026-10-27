//! Operating-system boundary for virtual FIDO HID transports.
//!
//! This crate currently defines the seam only. It does not create a device.

use std::fmt;

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

/// Lifecycle state exposed to the application UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    Detached,
    Attached,
}

/// Errors returned by a platform-specific virtual HID implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformError {
    /// The target operating system does not have an implementation yet.
    NotImplemented(HostPlatform),
}

impl fmt::Display for PlatformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented(platform) => {
                write!(formatter, "virtual HID is not implemented for {platform:?}")
            }
        }
    }
}

impl std::error::Error for PlatformError {}

/// Contract implemented by each operating-system transport adapter.
pub trait VirtualHidBackend {
    /// Reports whether this backend can create a virtual FIDO HID device.
    fn is_available(&self) -> bool;

    /// Attaches the virtual device to the operating system.
    fn attach(&mut self) -> Result<(), PlatformError>;

    /// Detaches the virtual device from the operating system.
    fn detach(&mut self) -> Result<(), PlatformError>;

    /// Returns the current attachment state.
    fn state(&self) -> DeviceState;
}

/// Placeholder backend that fails closed until a native adapter is implemented.
#[derive(Debug, Default)]
pub struct UnavailableBackend;

impl VirtualHidBackend for UnavailableBackend {
    fn is_available(&self) -> bool {
        false
    }

    fn attach(&mut self) -> Result<(), PlatformError> {
        Err(PlatformError::NotImplemented(HostPlatform::current()))
    }

    fn detach(&mut self) -> Result<(), PlatformError> {
        Ok(())
    }

    fn state(&self) -> DeviceState {
        DeviceState::Detached
    }
}
