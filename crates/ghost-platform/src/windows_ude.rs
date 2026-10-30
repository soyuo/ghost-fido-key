//! Windows UDE user-mode boundary.
//!
//! The actual UdeCx/KMDF implementation lives under `platforms/windows/ude`.
//! The adapter permits a runtime attempt only when a loaded driver responds
//! to the documented control endpoint with an assigned identity, all required
//! capability bits, and the exact FIDO report profile. `Configured` does not
//! mean this adapter verified the driver's signature or trust, nor does it
//! establish report round-trip or browser interoperability. Windows driver
//! loading policy remains responsible for whether a driver can be loaded.
#![allow(unsafe_code)]

use std::{
    fs::OpenOptions,
    io,
    os::windows::io::AsRawHandle,
    path::{Path, PathBuf},
    thread,
    time::Duration,
    time::Instant,
};

use windows::Win32::{Foundation::HANDLE, System::IO::DeviceIoControl};

use crate::{
    CapabilityState, CapabilityStatus, DeviceState, HostPlatform, PlatformCapabilities,
    PlatformError, PlatformErrorKind, VirtualHidBackend,
};

/// User-mode control endpoint reserved by the native UDE driver.
pub const DEFAULT_UDE_CONTROL_PATH: &str = r"\\.\GhostFidoUde";

const IOCTL_GHOST_FIDO_UDE_QUERY_STATUS: u32 = ctl_code(0x22, 0x800, 0, 1);
const IOCTL_GHOST_FIDO_UDE_ATTACH: u32 = ctl_code(0x22, 0x801, 0, 2);
const IOCTL_GHOST_FIDO_UDE_DETACH: u32 = ctl_code(0x22, 0x802, 0, 2);
const IOCTL_GHOST_FIDO_UDE_WRITE_INPUT_REPORT: u32 = ctl_code(0x22, 0x803, 0, 2);
const IOCTL_GHOST_FIDO_UDE_READ_OUTPUT_REPORT: u32 = ctl_code(0x22, 0x804, 0, 1);
const UDE_PROTOCOL_MAJOR: u32 = 1;
const UDE_PROTOCOL_MINOR: u32 = 2;
const UDE_STATUS_SIGNATURE: u32 = 0x4455_4647;
const UDE_STATUS_REQUEST_SIZE: u32 = 16;
const UDE_STATUS_RESPONSE_SIZE: usize = 44;
const UDE_MAX_STATUS_SIZE: usize = 256;
const UDE_REQUIRED_CAPABILITIES: u32 = 0x0f;
const FIDO_REPORT_SIZE: u32 = 64;
const OPERATION_REQUEST_SIZE: u32 = 16;
const INPUT_REPORT_REQUEST_SIZE: u32 = 84;
const OUTPUT_REPORT_REQUEST_SIZE: u32 = 16;
const OUTPUT_REPORT_RESPONSE_SIZE: usize = 84;
const ERROR_NO_MORE_ITEMS_HRESULT: i32 = 0x8007_0103u32 as i32;
const ERROR_DEVICE_NOT_CONNECTED_HRESULT: i32 = 0x8007_048fu32 as i32;
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

#[repr(C)]
struct UdeOperationRequest {
    size: u32,
    protocol_major: u32,
    protocol_minor: u32,
    reserved: u32,
}

#[repr(C)]
struct UdeInputReportRequest {
    size: u32,
    protocol_major: u32,
    protocol_minor: u32,
    report_size: u32,
    reserved: u32,
    report: [u8; FIDO_REPORT_SIZE as usize],
}

#[repr(C)]
struct UdeOutputReportRequest {
    size: u32,
    protocol_major: u32,
    protocol_minor: u32,
    reserved: u32,
}

struct UdeOutputReportResponse {
    report: Vec<u8>,
}

struct UdeStatus {
    capabilities: u32,
    input_report_size: u32,
    output_report_size: u32,
    vendor_id: u32,
    product_id: u32,
}

impl UdeStatus {
    fn has_valid_identity(&self) -> bool {
        (1..=0xfffe).contains(&self.vendor_id) && (1..=0xfffe).contains(&self.product_id)
    }
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
            vendor_id: read_u32(36),
            product_id: read_u32(40),
        })
    }

    fn control_file(&self) -> Result<std::fs::File, UdeQueryError> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.control_path)
            .map_err(UdeQueryError::Open)
    }

    fn operation_request() -> UdeOperationRequest {
        UdeOperationRequest {
            size: OPERATION_REQUEST_SIZE,
            protocol_major: UDE_PROTOCOL_MAJOR,
            protocol_minor: UDE_PROTOCOL_MINOR,
            reserved: 0,
        }
    }

    fn send_operation(&self, ioctl: u32) -> Result<(), UdeQueryError> {
        let file = self.control_file()?;
        let request = Self::operation_request();
        let mut bytes_returned = 0u32;
        // SAFETY: the fixed-size request is initialized and the byte-count
        // pointer remains writable for the duration of DeviceIoControl.
        unsafe {
            DeviceIoControl(
                HANDLE(file.as_raw_handle()),
                ioctl,
                Some((&request as *const UdeOperationRequest).cast()),
                OPERATION_REQUEST_SIZE,
                None,
                0,
                Some(&mut bytes_returned),
                None,
            )
        }
        .map_err(|error| UdeQueryError::Ioctl {
            code: error.code().0,
            detail: error.to_string(),
        })?;
        if bytes_returned != 0 {
            return Err(UdeQueryError::Protocol(format!(
                "operation returned {bytes_returned} unexpected response bytes"
            )));
        }
        Ok(())
    }

    fn write_input_report(&self, report: &[u8]) -> Result<(), UdeQueryError> {
        let report: [u8; FIDO_REPORT_SIZE as usize] = report.try_into().map_err(|_| {
            UdeQueryError::Protocol(format!("FIDO HID reports must be {FIDO_REPORT_SIZE} bytes"))
        })?;
        let file = self.control_file()?;
        let request = UdeInputReportRequest {
            size: INPUT_REPORT_REQUEST_SIZE,
            protocol_major: UDE_PROTOCOL_MAJOR,
            protocol_minor: UDE_PROTOCOL_MINOR,
            report_size: FIDO_REPORT_SIZE,
            reserved: 0,
            report,
        };
        let mut bytes_returned = 0u32;
        // SAFETY: the report record is fixed-size and initialized; the output
        // pointer is valid for the synchronous DeviceIoControl call.
        unsafe {
            DeviceIoControl(
                HANDLE(file.as_raw_handle()),
                IOCTL_GHOST_FIDO_UDE_WRITE_INPUT_REPORT,
                Some((&request as *const UdeInputReportRequest).cast()),
                INPUT_REPORT_REQUEST_SIZE,
                None,
                0,
                Some(&mut bytes_returned),
                None,
            )
        }
        .map_err(|error| UdeQueryError::Ioctl {
            code: error.code().0,
            detail: error.to_string(),
        })?;
        if bytes_returned != 0 {
            return Err(UdeQueryError::Protocol(format!(
                "report write returned {bytes_returned} unexpected response bytes"
            )));
        }
        Ok(())
    }

    fn read_output_report(&self) -> Result<UdeOutputReportResponse, UdeQueryError> {
        let file = self.control_file()?;
        let request = UdeOutputReportRequest {
            size: OUTPUT_REPORT_REQUEST_SIZE,
            protocol_major: UDE_PROTOCOL_MAJOR,
            protocol_minor: UDE_PROTOCOL_MINOR,
            reserved: 0,
        };
        let mut response = [0u8; OUTPUT_REPORT_RESPONSE_SIZE];
        let mut bytes_returned = 0u32;
        // SAFETY: the request and response buffers have the exact ABI sizes;
        // DeviceIoControl writes no more than the provided response capacity.
        unsafe {
            DeviceIoControl(
                HANDLE(file.as_raw_handle()),
                IOCTL_GHOST_FIDO_UDE_READ_OUTPUT_REPORT,
                Some((&request as *const UdeOutputReportRequest).cast()),
                OUTPUT_REPORT_REQUEST_SIZE,
                Some(response.as_mut_ptr().cast()),
                OUTPUT_REPORT_RESPONSE_SIZE as u32,
                Some(&mut bytes_returned),
                None,
            )
        }
        .map_err(|error| UdeQueryError::Ioctl {
            code: error.code().0,
            detail: error.to_string(),
        })?;

        if bytes_returned as usize != OUTPUT_REPORT_RESPONSE_SIZE {
            return Err(UdeQueryError::Protocol(format!(
                "driver returned {bytes_returned} output-report bytes; expected {OUTPUT_REPORT_RESPONSE_SIZE}"
            )));
        }
        let read_u32 = |offset: usize| {
            u32::from_le_bytes(
                response[offset..offset + 4]
                    .try_into()
                    .expect("fixed-size output-report response"),
            )
        };
        if read_u32(0) as usize != OUTPUT_REPORT_RESPONSE_SIZE
            || read_u32(4) != UDE_PROTOCOL_MAJOR
            || read_u32(8) > UDE_PROTOCOL_MINOR
            || read_u32(12) != FIDO_REPORT_SIZE
            || read_u32(16) != 0
        {
            return Err(UdeQueryError::Protocol(
                "driver returned an invalid output-report response header".to_owned(),
            ));
        }
        Ok(UdeOutputReportResponse {
            report: response[20..].to_vec(),
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
            Ok(status) if !status.has_valid_identity() => CapabilityStatus::unavailable(
                CapabilityState::NotImplemented,
                format!(
                    "UDE driver identity is not a valid assigned USB VID/PID: vendor=0x{:08x}, product=0x{:08x}; configure product-assigned 16-bit IDs",
                    status.vendor_id, status.product_id
                ),
            ),
            Ok(status)
                if status.capabilities & UDE_REQUIRED_CAPABILITIES == UDE_REQUIRED_CAPABILITIES
                    && status.input_report_size == FIDO_REPORT_SIZE
                    && status.output_report_size == FIDO_REPORT_SIZE =>
            {
                CapabilityStatus::configured(
                    "the UDE driver reports an assigned identity and compatible FIDO HID profile; starting it will exercise runtime transport, but browser interoperability remains unverified",
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
        if self.state == DeviceState::Attached {
            return Ok(());
        }
        self.state = DeviceState::Starting;
        match self.send_operation(IOCTL_GHOST_FIDO_UDE_ATTACH) {
            Ok(()) => {
                self.state = DeviceState::Attached;
                Ok(())
            }
            Err(error) => {
                self.state = DeviceState::Failed;
                Err(self.map_operation_error("attach", error))
            }
        }
    }

    fn detach(&mut self) -> Result<(), PlatformError> {
        self.state = DeviceState::Stopping;
        match self.send_operation(IOCTL_GHOST_FIDO_UDE_DETACH) {
            Ok(()) => {
                self.state = DeviceState::Detached;
                Ok(())
            }
            Err(UdeQueryError::Ioctl { code, .. })
                if code == ERROR_DEVICE_NOT_CONNECTED_HRESULT =>
            {
                self.state = DeviceState::Detached;
                Ok(())
            }
            Err(error) => {
                self.state = DeviceState::Failed;
                Err(self.map_operation_error("detach", error))
            }
        }
    }

    fn state(&self) -> DeviceState {
        self.state
    }

    fn send_input_report(&mut self, report: &[u8]) -> Result<(), PlatformError> {
        if report.len() != FIDO_REPORT_SIZE as usize {
            return Err(Self::error(
                PlatformErrorKind::InvalidReport,
                format!("FIDO HID reports must be {FIDO_REPORT_SIZE} bytes"),
            ));
        }
        if self.state != DeviceState::Attached {
            return Err(Self::error(
                PlatformErrorKind::Unsupported,
                "cannot send a report while the device is detached",
            ));
        }
        self.write_input_report(report)
            .map_err(|error| self.map_operation_error("write input report", error))
    }

    fn receive_output_report(&mut self, timeout: Duration) -> Result<Vec<u8>, PlatformError> {
        if self.state != DeviceState::Attached {
            return Err(Self::error(
                PlatformErrorKind::Unsupported,
                "cannot receive a report while the device is detached",
            ));
        }
        let started = Instant::now();
        loop {
            match self.read_output_report() {
                Ok(response) => return Ok(response.report),
                Err(UdeQueryError::Ioctl { code, .. }) if code == ERROR_NO_MORE_ITEMS_HRESULT => {
                    let elapsed = started.elapsed();
                    if elapsed >= timeout {
                        return Err(Self::error(
                            PlatformErrorKind::Timeout,
                            "timed out waiting for a UDE output report",
                        ));
                    }
                    thread::sleep(Duration::from_millis(2).min(timeout - elapsed));
                }
                Err(UdeQueryError::Ioctl { code, detail })
                    if code == ERROR_DEVICE_NOT_CONNECTED_HRESULT =>
                {
                    self.state = DeviceState::Failed;
                    return Err(Self::error(PlatformErrorKind::Io, detail));
                }
                Err(error) => {
                    self.state = DeviceState::Failed;
                    return Err(self.map_operation_error("read output report", error));
                }
            }
        }
    }
}

impl WindowsUdeBackend {
    fn map_operation_error(&self, operation: &str, error: UdeQueryError) -> PlatformError {
        match error {
            UdeQueryError::Open(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                Self::error(
                    PlatformErrorKind::PermissionDenied,
                    format!("permission denied while attempting to {operation}"),
                )
            }
            UdeQueryError::Open(error) if error.kind() == io::ErrorKind::NotFound => Self::error(
                PlatformErrorKind::DriverMissing,
                format!("UDE control endpoint is missing while attempting to {operation}"),
            ),
            UdeQueryError::Open(error) => Self::error(
                PlatformErrorKind::Io,
                format!("failed to open the UDE control endpoint for {operation}: {error}"),
            ),
            UdeQueryError::Ioctl { code, detail } if code == ERROR_ACCESS_DENIED_HRESULT => {
                Self::error(
                    PlatformErrorKind::PermissionDenied,
                    format!("permission denied while attempting to {operation}: {detail}"),
                )
            }
            UdeQueryError::Ioctl { code, detail }
                if code == ERROR_INVALID_FUNCTION_HRESULT
                    || code == ERROR_INVALID_PARAMETER_HRESULT
                    || code == ERROR_NOT_SUPPORTED_HRESULT =>
            {
                Self::error(
                    PlatformErrorKind::NotImplemented,
                    format!("the UDE driver rejected {operation}: {detail}"),
                )
            }
            UdeQueryError::Ioctl { detail, .. } => Self::error(
                PlatformErrorKind::Io,
                format!("UDE {operation} IOCTL failed: {detail}"),
            ),
            UdeQueryError::Protocol(detail) => Self::error(
                PlatformErrorKind::InvalidReport,
                format!("invalid UDE response during {operation}: {detail}"),
            ),
        }
    }
}
