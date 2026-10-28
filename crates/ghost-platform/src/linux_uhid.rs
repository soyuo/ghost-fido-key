//! Linux UHID userspace transport.
//!
//! The backend owns `/dev/uhid` for one virtual FIDO HID device. It does not
//! implement CTAPHID itself; callers provide complete 64-byte reports.

use std::{
    fs::{File, OpenOptions},
    io,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use uhid_virt::{Bus, CreateParams, OutputEvent, ReportType, StreamError, UHIDDevice};

use crate::{
    CapabilityState, CapabilityStatus, DeviceState, HostPlatform, PlatformCapabilities,
    PlatformError, PlatformErrorKind, VirtualHidBackend,
};

/// Linux UHID character device used by the kernel userspace HID API.
pub const DEFAULT_UHID_PATH: &str = "/dev/uhid";

/// CTAPHID report size used by the initial FIDO HID transport.
pub const FIDO_REPORT_SIZE: usize = 64;

/// FIDO Alliance CTAPHID HID report descriptor for 64-byte IN/OUT reports.
///
/// The FIDO usage page (`0xF1D0`) and CTAPHID usage (`0x01`) are how browsers
/// discover this HID as a FIDO authenticator.
pub const FIDO_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xd0, 0xf1, // Usage Page (FIDO Alliance)
    0x09, 0x01, // Usage (CTAPHID)
    0xa1, 0x01, // Collection (Application)
    0x09, 0x20, // Usage (Input Report Data)
    0x15, 0x00, // Logical Minimum (0)
    0x26, 0xff, 0x00, // Logical Maximum (255)
    0x75, 0x08, // Report Size (8)
    0x95, 0x40, // Report Count (64)
    0x81, 0x02, // Input (Data, Variable, Absolute)
    0x09, 0x21, // Usage (Output Report Data)
    0x15, 0x00, // Logical Minimum (0)
    0x26, 0xff, 0x00, // Logical Maximum (255)
    0x75, 0x08, // Report Size (8)
    0x95, 0x40, // Report Count (64)
    0x91, 0x02, // Output (Data, Variable, Absolute)
    0xc0, // End Collection
];

/// Synchronous Linux `/dev/uhid` backend.
pub struct LinuxUhidBackend {
    path: PathBuf,
    device: Option<UHIDDevice<File>>,
    state: DeviceState,
}

impl LinuxUhidBackend {
    #[must_use]
    pub fn new() -> Self {
        Self::with_path(DEFAULT_UHID_PATH)
    }

    #[must_use]
    pub fn with_path(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            device: None,
            state: DeviceState::Detached,
        }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn capabilities(&self) -> PlatformCapabilities {
        let virtual_hid = match probe_uhid(&self.path) {
            Ok(()) => CapabilityStatus::available(),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                CapabilityStatus::unavailable(
                    CapabilityState::PermissionRequired,
                    format!("{} requires read/write access", self.path.display()),
                )
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => CapabilityStatus::unavailable(
                CapabilityState::DriverMissing,
                format!("{} is not available", self.path.display()),
            ),
            Err(error) => CapabilityStatus::unavailable(
                CapabilityState::Error,
                format!("failed to inspect {}: {error}", self.path.display()),
            ),
        };

        PlatformCapabilities {
            virtual_hid,
            protected_key_storage: CapabilityStatus::unavailable(
                CapabilityState::NotImplemented,
                "Linux protected key provider is not implemented",
            ),
            user_verification: CapabilityStatus::unavailable(
                CapabilityState::NotImplemented,
                "Linux user verification provider is not implemented",
            ),
        }
    }

    fn error(kind: PlatformErrorKind, detail: impl Into<String>) -> PlatformError {
        PlatformError::new(kind, HostPlatform::Linux, detail)
    }

    fn read_until(&mut self, timeout: Duration) -> Result<OutputEvent, PlatformError> {
        let deadline = Instant::now() + timeout;
        let device = self.device.as_mut().ok_or_else(|| {
            Self::error(
                PlatformErrorKind::Unsupported,
                "virtual FIDO HID is not attached",
            )
        })?;

        loop {
            match device.read() {
                Ok(event) => return Ok(event),
                Err(StreamError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(Self::error(
                            PlatformErrorKind::Timeout,
                            "timed out waiting for a UHID event",
                        ));
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                Err(StreamError::Io(error)) => {
                    self.state = DeviceState::Failed;
                    return Err(Self::error(PlatformErrorKind::Io, error.to_string()));
                }
                Err(_) => {
                    self.state = DeviceState::Failed;
                    return Err(Self::error(
                        PlatformErrorKind::InvalidReport,
                        "kernel returned an unsupported UHID event",
                    ));
                }
            }
        }
    }
}

impl Default for LinuxUhidBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualHidBackend for LinuxUhidBackend {
    fn availability(&self) -> CapabilityStatus {
        self.capabilities().virtual_hid
    }

    fn attach(&mut self) -> Result<(), PlatformError> {
        if self.device.is_some() {
            return Ok(());
        }
        self.state = DeviceState::Starting;
        let params = CreateParams {
            name: "Ghost FIDO Key".to_owned(),
            phys: "".to_owned(),
            uniq: "ghost-fido-key".to_owned(),
            bus: Bus::VIRTUAL,
            // The project does not claim a manufacturer identity. The FIDO
            // usage page, not a third-party VID/PID, drives discovery.
            vendor: 0,
            product: 0,
            version: 1,
            country: 0,
            rd_data: FIDO_REPORT_DESCRIPTOR.to_vec(),
        };
        self.device = Some(
            UHIDDevice::create_with_path(params, &self.path).map_err(|error| {
                self.state = DeviceState::Failed;
                let kind = match error.kind() {
                    io::ErrorKind::PermissionDenied => PlatformErrorKind::PermissionDenied,
                    io::ErrorKind::NotFound => PlatformErrorKind::DriverMissing,
                    _ => PlatformErrorKind::Io,
                };
                Self::error(
                    kind,
                    format!("failed to create {}: {error}", self.path.display()),
                )
            })?,
        );

        match self.read_until(Duration::from_secs(2))? {
            OutputEvent::Start { .. } => {
                self.state = DeviceState::Attached;
                Ok(())
            }
            _ => {
                self.state = DeviceState::Failed;
                Err(Self::error(
                    PlatformErrorKind::Io,
                    "UHID did not acknowledge device creation with UHID_START",
                ))
            }
        }
    }

    fn detach(&mut self) -> Result<(), PlatformError> {
        let Some(mut device) = self.device.take() else {
            self.state = DeviceState::Detached;
            return Ok(());
        };
        self.state = DeviceState::Stopping;
        device
            .destroy()
            .map_err(|error| Self::error(PlatformErrorKind::Io, error.to_string()))?;
        self.state = DeviceState::Detached;
        Ok(())
    }

    fn state(&self) -> DeviceState {
        self.state
    }

    fn send_input_report(&mut self, report: &[u8]) -> Result<(), PlatformError> {
        if report.len() != FIDO_REPORT_SIZE {
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
        self.device
            .as_mut()
            .ok_or_else(|| Self::error(PlatformErrorKind::Unsupported, "device handle is missing"))?
            .write(report)
            .map(|_| ())
            .map_err(|error| Self::error(PlatformErrorKind::Io, error.to_string()))
    }

    fn receive_output_report(&mut self, timeout: Duration) -> Result<Vec<u8>, PlatformError> {
        if self.state != DeviceState::Attached {
            return Err(Self::error(
                PlatformErrorKind::Unsupported,
                "cannot receive a report while the device is detached",
            ));
        }
        loop {
            match self.read_until(timeout)? {
                OutputEvent::Output { data } if data.len() == FIDO_REPORT_SIZE => return Ok(data),
                OutputEvent::Output { data } => {
                    return Err(Self::error(
                        PlatformErrorKind::InvalidReport,
                        format!("received {} bytes, expected {FIDO_REPORT_SIZE}", data.len()),
                    ));
                }
                OutputEvent::Open | OutputEvent::Close | OutputEvent::Start { .. } => {}
                OutputEvent::Stop => {
                    self.state = DeviceState::Failed;
                    return Err(Self::error(
                        PlatformErrorKind::Io,
                        "kernel stopped the UHID device",
                    ));
                }
                OutputEvent::GetReport { .. } | OutputEvent::SetReport { .. } => {
                    return Err(Self::error(
                        PlatformErrorKind::Unsupported,
                        "feature reports are not supported by the transport contract",
                    ));
                }
            }
        }
    }
}

impl Drop for LinuxUhidBackend {
    fn drop(&mut self) {
        if let Some(mut device) = self.device.take() {
            let _ = device.destroy();
        }
    }
}

fn probe_uhid(path: &Path) -> io::Result<()> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map(|_| ())
}
