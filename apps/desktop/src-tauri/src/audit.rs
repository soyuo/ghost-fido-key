use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const AUDIT_TARGET: &str = "ghost_fido::audit";
const MAX_LOG_BYTES: u64 = 1_048_576;

static LOGGER: OnceLock<BestEffortLogger> = OnceLock::new();

#[derive(Clone, Copy)]
pub(crate) enum Event {
    RuntimeStartRequested,
    RuntimeStarted,
    RuntimeStopped,
    RuntimeFailure,
    CredentialStoreInitialization,
    UserApproval,
    ClientPinConfiguration,
    CredentialDeletion,
    AuthenticatorReset,
}

impl Event {
    fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeStartRequested => "runtime_start_requested",
            Self::RuntimeStarted => "runtime_started",
            Self::RuntimeStopped => "runtime_stopped",
            Self::RuntimeFailure => "runtime_failure",
            Self::CredentialStoreInitialization => "credential_store_initialization",
            Self::UserApproval => "user_approval",
            Self::ClientPinConfiguration => "client_pin_configuration",
            Self::CredentialDeletion => "credential_deletion",
            Self::AuthenticatorReset => "authenticator_reset",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    Success,
    Failure,
    Rejected,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Rejected => "rejected",
        }
    }
}

struct BestEffortLogger {
    file: Mutex<Option<LogFile>>,
}

struct LogFile {
    file: File,
    bytes_written: u64,
}

impl BestEffortLogger {
    fn new(log_dir: Option<PathBuf>) -> Self {
        let file = log_dir.and_then(open_log_file);
        Self {
            file: Mutex::new(file),
        }
    }
}

impl log::Log for BestEffortLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.target() == AUDIT_TARGET && metadata.level() <= log::Level::Info
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let Ok(mut state) = self.file.lock() else {
            return;
        };
        let Some(log_file) = state.as_mut() else {
            return;
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default();
        let line = format!("{timestamp} [{}] {}\n", record.level(), record.args());
        if log_file.bytes_written.saturating_add(line.len() as u64) > MAX_LOG_BYTES {
            if log_file.file.set_len(0).is_err() {
                *state = None;
                return;
            }
            log_file.bytes_written = 0;
        }
        if log_file.file.write_all(line.as_bytes()).is_err() {
            *state = None;
            return;
        }
        log_file.bytes_written = log_file.bytes_written.saturating_add(line.len() as u64);
    }

    fn flush(&self) {
        if let Ok(mut state) = self.file.lock() {
            if let Some(log_file) = state.as_mut() {
                let _ = log_file.file.flush();
            }
        }
    }
}

fn open_log_file(log_dir: PathBuf) -> Option<LogFile> {
    if fs::create_dir_all(&log_dir).is_err() {
        return None;
    }
    let path = log_dir.join("events.log");
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()?;
    let mut bytes_written = file.metadata().ok()?.len();
    if bytes_written > MAX_LOG_BYTES {
        file.set_len(0).ok()?;
        bytes_written = 0;
    }
    Some(LogFile {
        file,
        bytes_written,
    })
}

pub(crate) fn init(log_dir: Option<PathBuf>) {
    let logger = LOGGER.get_or_init(|| BestEffortLogger::new(log_dir));
    if log::set_logger(logger).is_ok() {
        log::set_max_level(log::LevelFilter::Info);
    }
}

pub(crate) fn record(event: Event, outcome: Outcome) {
    if outcome == Outcome::Failure {
        log::warn!(target: AUDIT_TARGET, "event={} outcome={}", event.as_str(), outcome.as_str());
    } else {
        log::info!(target: AUDIT_TARGET, "event={} outcome={}", event.as_str(), outcome.as_str());
    }
}
