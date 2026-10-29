use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
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
    log_path: Option<PathBuf>,
}

struct LogFile {
    file: File,
    bytes_written: u64,
}

impl BestEffortLogger {
    fn new(log_dir: Option<PathBuf>) -> Self {
        let log_path = log_dir
            .as_ref()
            .map(|directory| directory.join("events.log"));
        let file = log_dir.and_then(open_log_file);
        Self {
            file: Mutex::new(file),
            log_path,
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

pub(crate) fn read_log() -> Option<String> {
    let path = LOGGER.get()?.log_path.as_ref()?;
    let file = File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_LOG_BYTES).read_to_end(&mut bytes).ok()?;

    let contents = String::from_utf8_lossy(&bytes);
    let mut redacted = String::new();
    for line in contents.lines() {
        let Some(line) = sanitize_log_line(line) else {
            continue;
        };
        if redacted.len().saturating_add(line.len() + 1) > MAX_LOG_BYTES as usize {
            break;
        }
        redacted.push_str(&line);
        redacted.push('\n');
    }
    Some(redacted)
}

fn sanitize_log_line(line: &str) -> Option<String> {
    let (timestamp, remainder) = line.split_once(" [")?;
    if timestamp.len() > 20
        || timestamp.is_empty()
        || !timestamp.bytes().all(|byte| byte.is_ascii_digit())
        || timestamp.parse::<u64>().is_err()
    {
        return None;
    }

    let (level, fields) = remainder.split_once("] ")?;
    let fields = fields.strip_prefix("event=")?;
    let (event, outcome) = fields.split_once(" outcome=")?;
    let known_event = matches!(
        event,
        "runtime_start_requested"
            | "runtime_started"
            | "runtime_stopped"
            | "runtime_failure"
            | "credential_store_initialization"
            | "user_approval"
            | "client_pin_configuration"
            | "credential_deletion"
            | "authenticator_reset"
    );
    let valid_level_and_outcome = matches!(
        (level, outcome),
        ("INFO", "success" | "rejected") | ("WARN", "failure")
    );
    if !known_event || !valid_level_and_outcome {
        return None;
    }

    Some(format!(
        "{timestamp} [{level}] event={event} outcome={outcome}"
    ))
}
