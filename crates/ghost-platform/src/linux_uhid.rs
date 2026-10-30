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
    product_identity: Option<(u16, u16)>,
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
            product_identity: configured_product_identity(),
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
        let virtual_hid = match self.product_identity {
            None => CapabilityStatus::unavailable(
                CapabilityState::Unsupported,
                "Linux virtual HID requires explicitly assigned GHOST_FIDO_LINUX_VENDOR_ID and GHOST_FIDO_LINUX_PRODUCT_ID build values",
            ),
            Some(_) => match probe_uhid(&self.path) {
                Ok(()) => CapabilityStatus::available(),
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                    CapabilityStatus::unavailable(
                        CapabilityState::PermissionRequired,
                        format!("{} requires read/write access", self.path.display()),
                    )
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    CapabilityStatus::unavailable(
                        CapabilityState::DriverMissing,
                        format!("{} is not available", self.path.display()),
                    )
                }
                Err(error) => CapabilityStatus::unavailable(
                    CapabilityState::Error,
                    format!("failed to inspect {}: {error}", self.path.display()),
                ),
            },
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

    fn fail_startup(&mut self, error: PlatformError) -> PlatformError {
        self.state = DeviceState::Failed;
        let Some(mut device) = self.device.take() else {
            return error;
        };

        if let Err(cleanup_error) = device.destroy() {
            self.device = Some(device);
            return Self::error(
                PlatformErrorKind::Io,
                format!(
                    "{}; failed to destroy partially created UHID device: {cleanup_error}",
                    error.detail
                ),
            );
        }

        error
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
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(Self::error(
                            PlatformErrorKind::Timeout,
                            "timed out waiting for a UHID event",
                        ));
                    }
                    thread::sleep(remaining.min(Duration::from_millis(1)));
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
        if self.state == DeviceState::Attached {
            return if self.device.is_some() {
                Ok(())
            } else {
                self.state = DeviceState::Failed;
                Err(Self::error(
                    PlatformErrorKind::Io,
                    "UHID backend is marked attached but its device handle is missing",
                ))
            };
        }
        if let Some(mut device) = self.device.take() {
            self.state = DeviceState::Stopping;
            if let Err(error) = device.destroy() {
                self.device = Some(device);
                self.state = DeviceState::Failed;
                return Err(Self::error(
                    PlatformErrorKind::Io,
                    format!("failed to clean up a previous UHID attach attempt: {error}"),
                ));
            }
        }
        let Some((vendor, product)) = self.product_identity else {
            self.state = DeviceState::Failed;
            return Err(Self::error(
                PlatformErrorKind::Unsupported,
                "Linux virtual HID cannot start without explicitly assigned vendor and product IDs",
            ));
        };
        self.state = DeviceState::Starting;
        let params = CreateParams {
            name: "Ghost FIDO Key".to_owned(),
            phys: "".to_owned(),
            uniq: "ghost-fido-key".to_owned(),
            bus: Bus::VIRTUAL,
            vendor: u32::from(vendor),
            product: u32::from(product),
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

        match self.read_until(Duration::from_secs(2)) {
            Err(error) => Err(self.fail_startup(error)),
            Ok(OutputEvent::Start { .. }) => {
                self.state = DeviceState::Attached;
                Ok(())
            }
            Ok(_) => Err(self.fail_startup(Self::error(
                PlatformErrorKind::Io,
                "UHID did not acknowledge device creation with UHID_START",
            ))),
        }
    }

    fn detach(&mut self) -> Result<(), PlatformError> {
        let Some(mut device) = self.device.take() else {
            self.state = DeviceState::Detached;
            return Ok(());
        };
        self.state = DeviceState::Stopping;
        match device.destroy() {
            Ok(_) => {
                self.state = DeviceState::Detached;
                Ok(())
            }
            Err(error) => {
                self.device = Some(device);
                self.state = DeviceState::Failed;
                Err(Self::error(PlatformErrorKind::Io, error.to_string()))
            }
        }
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
        let deadline = Instant::now() + timeout;
        let mut first_read = true;
        loop {
            let now = Instant::now();
            if !first_read && now >= deadline {
                return Err(Self::error(
                    PlatformErrorKind::Timeout,
                    "timed out waiting for a UHID output report",
                ));
            }
            first_read = false;
            let remaining = deadline.saturating_duration_since(now);
            match self.read_until(remaining)? {
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

fn configured_product_identity() -> Option<(u16, u16)> {
    Some((
        parse_product_id(option_env!("GHOST_FIDO_LINUX_VENDOR_ID")?)?,
        parse_product_id(option_env!("GHOST_FIDO_LINUX_PRODUCT_ID")?)?,
    ))
}

fn parse_product_id(value: &str) -> Option<u16> {
    let value = value.trim();
    let parsed = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(|| value.parse::<u32>(), |hex| u32::from_str_radix(hex, 16))
        .ok()?;
    (1..0xFFFF).contains(&parsed).then_some(parsed as u16)
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
