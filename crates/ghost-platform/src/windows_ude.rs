//! Windows UDE user-mode boundary.
//!
//! The actual UdeCx/KMDF implementation lives under `platforms/windows/ude`.
//! This Rust adapter intentionally fails closed until a signed driver exposes
//! the documented control endpoint and IOCTL contract.
#![allow(unsafe_code)]

use std::{
    fs::OpenOptions,
    io,
    os::windows::io::AsRawHandle,
    path::{Path, PathBuf},
    time::Duration,
};

use windows::Win32::{Foundation::HANDLE, System::IO::DeviceIoControl};

use crate::{
    CapabilityState, CapabilityStatus, DeviceState, HostPlatform, PlatformCapabilities,
    PlatformError, PlatformErrorKind, VirtualHidBackend,
};

/// User-mode control endpoint reserved by the native UDE driver.
pub const DEFAULT_UDE_CONTROL_PATH: &str = r"\\.\GhostFidoUde";

const IOCTL_GHOST_FIDO_UDE_QUERY_STATUS: u32 = ctl_code(0x22, 0x800, 0, 1);
const UDE_PROTOCOL_MAJOR: u32 = 1;
const UDE_PROTOCOL_MINOR: u32 = 0;
const UDE_STATUS_SIGNATURE: u32 = 0x4455_4647;
const UDE_STATUS_REQUEST_SIZE: u32 = 16;
const UDE_STATUS_RESPONSE_SIZE: usize = 36;
const UDE_MAX_STATUS_SIZE: usize = 256;
const UDE_REQUIRED_CAPABILITIES: u32 = 0x0f;
const FIDO_REPORT_SIZE: u32 = 64;
const ERROR_ACCESS_DENIED_HRESULT: i32 = 0x8007_0005u32 as i32;
const ERROR_INVALID_FUNCTION_HRESULT: i32 = 0x8007_0001u32 as i32;
const ERROR_INVALID_PARAMETER_HRESULT: i32 = 0x8007_0057u32 as i32;
const ERROR_NOT_SUPPORTED_HRESULT: i32 = 0x8007_0032u32 as i32;

const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

#[repr(C)]
struct UdeStatusRequest {
    size: u32,
    protocol_major: u32,
    protocol_minor: u32,
    reserved: u32,
}

struct UdeStatus {
    capabilities: u32,
    input_report_size: u32,
    output_report_size: u32,
}

enum UdeQueryError {
    Open(io::Error),
    Ioctl { code: i32, detail: String },
    Protocol(String),
}

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

    fn query_status(&self) -> Result<UdeStatus, UdeQueryError> {
        let file = OpenOptions::new()
            .read(true)
            .open(&self.control_path)
            .map_err(UdeQueryError::Open)?;
        let request = UdeStatusRequest {
            size: UDE_STATUS_REQUEST_SIZE,
            protocol_major: UDE_PROTOCOL_MAJOR,
            protocol_minor: UDE_PROTOCOL_MINOR,
            reserved: 0,
        };
        let mut response = [0u8; UDE_MAX_STATUS_SIZE];
        let mut bytes_returned = 0u32;
        // SAFETY: the request is a fixed-size initialized protocol record; the
        // response buffer and byte-count pointer remain writable for the call.
        unsafe {
            DeviceIoControl(
                HANDLE(file.as_raw_handle()),
                IOCTL_GHOST_FIDO_UDE_QUERY_STATUS,
                Some((&request as *const UdeStatusRequest).cast()),
                UDE_STATUS_REQUEST_SIZE,
                Some(response.as_mut_ptr().cast()),
                UDE_MAX_STATUS_SIZE as u32,
                Some(&mut bytes_returned),
                None,
            )
        }
        .map_err(|error| UdeQueryError::Ioctl {
            code: error.code().0,
            detail: error.to_string(),
        })?;

        let returned = usize::try_from(bytes_returned).map_err(|_| {
            UdeQueryError::Protocol("driver returned an invalid response length".to_owned())
        })?;
        if !(UDE_STATUS_RESPONSE_SIZE..=UDE_MAX_STATUS_SIZE).contains(&returned) {
            return Err(UdeQueryError::Protocol(format!(
                "driver returned {returned} status bytes; expected {UDE_STATUS_RESPONSE_SIZE}..={UDE_MAX_STATUS_SIZE}"
            )));
        }
        let read_u32 = |offset: usize| {
            u32::from_le_bytes(
                response[offset..offset + 4]
                    .try_into()
                    .expect("validated status prefix"),
            )
        };
        let declared_size = usize::try_from(read_u32(0)).map_err(|_| {
            UdeQueryError::Protocol("driver returned an invalid declared response size".to_owned())
        })?;
        if declared_size != returned {
            return Err(UdeQueryError::Protocol(format!(
                "driver declared {declared_size} status bytes but returned {returned}"
            )));
        }
        if read_u32(4) != UDE_STATUS_SIGNATURE {
            return Err(UdeQueryError::Protocol(
                "driver status signature does not match the UDE protocol".to_owned(),
            ));
        }
        if read_u32(8) != UDE_PROTOCOL_MAJOR {
            return Err(UdeQueryError::Protocol(format!(
                "unsupported UDE protocol major version {} (expected {UDE_PROTOCOL_MAJOR})",
                read_u32(8)
            )));
        }
        if read_u32(28) != 0 || read_u32(32) != 0 {
            return Err(UdeQueryError::Protocol(
                "driver status reserved fields must be zero".to_owned(),
            ));
        }

        Ok(UdeStatus {
            capabilities: read_u32(16),
            input_report_size: read_u32(20),
            output_report_size: read_u32(24),
        })
    }
}

impl Default for WindowsUdeBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualHidBackend for WindowsUdeBackend {
    fn availability(&self) -> CapabilityStatus {
        match self.query_status() {
            Ok(status)
                if status.capabilities & UDE_REQUIRED_CAPABILITIES == UDE_REQUIRED_CAPABILITIES
                    && status.input_report_size == FIDO_REPORT_SIZE
                    && status.output_report_size == FIDO_REPORT_SIZE =>
            {
                CapabilityStatus::unavailable(
                    CapabilityState::NotImplemented,
                    "the UDE driver reports a compatible FIDO HID profile, but Rust attach, detach, and report operations are not implemented",
                )
            }
            Ok(status) => CapabilityStatus::unavailable(
                CapabilityState::NotImplemented,
                format!(
                    "UDE readiness response is incomplete: capabilities=0x{:08x}, input report={}, output report={}",
                    status.capabilities, status.input_report_size, status.output_report_size
                ),
            ),
            Err(UdeQueryError::Open(error)) if error.kind() == io::ErrorKind::NotFound => {
                CapabilityStatus::unavailable(
                    CapabilityState::DriverMissing,
                    format!(
                        "UDE control endpoint {} is missing",
                        self.control_path.display()
                    ),
                )
            }
            Err(UdeQueryError::Open(error)) if error.kind() == io::ErrorKind::PermissionDenied => {
                CapabilityStatus::unavailable(
                    CapabilityState::PermissionRequired,
                    format!(
                        "{} requires driver access permission",
                        self.control_path.display()
                    ),
                )
            }
            Err(UdeQueryError::Open(error)) => CapabilityStatus::unavailable(
                CapabilityState::Error,
                format!("failed to open UDE control endpoint: {error}"),
            ),
            Err(UdeQueryError::Ioctl { code, .. }) if code == ERROR_ACCESS_DENIED_HRESULT => {
                CapabilityStatus::unavailable(
                    CapabilityState::PermissionRequired,
                    format!(
                        "{} requires driver access permission",
                        self.control_path.display()
                    ),
                )
            }
            Err(UdeQueryError::Ioctl { code, detail })
                if matches!(
                    code,
                    ERROR_INVALID_FUNCTION_HRESULT
                        | ERROR_INVALID_PARAMETER_HRESULT
                        | ERROR_NOT_SUPPORTED_HRESULT
                ) =>
            {
                CapabilityStatus::unavailable(
                    CapabilityState::NotImplemented,
                    format!("UDE driver does not provide a usable readiness handshake: {detail}"),
                )
            }
            Err(UdeQueryError::Ioctl { detail, .. }) => CapabilityStatus::unavailable(
                CapabilityState::Error,
                format!("UDE readiness IOCTL failed: {detail}"),
            ),
            Err(UdeQueryError::Protocol(detail)) => {
                CapabilityStatus::unavailable(CapabilityState::NotImplemented, detail)
            }
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
