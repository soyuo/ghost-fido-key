//! Transport-neutral CTAPHID report framing.

use core::fmt;

pub const HID_REPORT_SIZE: usize = 64;
pub const INIT_PAYLOAD_SIZE: usize = HID_REPORT_SIZE - 7;
pub const CONTINUATION_PAYLOAD_SIZE: usize = HID_REPORT_SIZE - 5;
pub const MAX_PAYLOAD_SIZE: usize = 7609;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CtapHidCommand {
    Init = 0x06,
    Ping = 0x01,
    Cbor = 0x10,
    Cancel = 0x11,
    Keepalive = 0x3b,
    Error = 0x3f,
}

impl CtapHidCommand {
    fn from_wire(value: u8) -> Result<Self, FrameError> {
        if value & 0x80 == 0 {
            return Err(FrameError::InvalidCommand(value));
        }
        match value & 0x7f {
            0x01 => Ok(Self::Ping),
            0x06 => Ok(Self::Init),
            0x10 => Ok(Self::Cbor),
            0x11 => Ok(Self::Cancel),
            0x3b => Ok(Self::Keepalive),
            0x3f => Ok(Self::Error),
            _ => Err(FrameError::InvalidCommand(value)),
        }
    }
    const fn wire(self) -> u8 {
        0x80 | self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    InvalidReportLength(usize),
    InvalidChannel,
    InvalidCommand(u8),
    PayloadTooLarge(usize),
    InvalidSequence { expected: u8, actual: u8 },
    UnexpectedContinuation,
    IncompleteMessage,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidReportLength(n) => write!(f, "CTAPHID report must be 64 bytes, got {n}"),
            Self::InvalidChannel => f.write_str("CTAPHID channel must be non-zero"),
            Self::InvalidCommand(c) => write!(f, "invalid CTAPHID command byte 0x{c:02x}"),
            Self::PayloadTooLarge(n) => write!(f, "CTAPHID payload is too large: {n} bytes"),
            Self::InvalidSequence { expected, actual } => {
                write!(f, "expected CTAPHID sequence {expected}, got {actual}")
            }
            Self::UnexpectedContinuation => {
                f.write_str("continuation received without an initialization frame")
            }
            Self::IncompleteMessage => f.write_str("CTAPHID message is incomplete"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtapHidMessage {
    pub channel: u32,
    pub command: CtapHidCommand,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtapHidAssembler {
    channel: u32,
    command: CtapHidCommand,
    expected_len: usize,
    next_sequence: u8,
    payload: Vec<u8>,
}

impl CtapHidAssembler {
    pub fn start(report: &[u8]) -> Result<Self, FrameError> {
        ensure_report(report)?;
        let channel = u32::from_be_bytes(report[0..4].try_into().expect("slice length"));
        if channel == 0 {
            return Err(FrameError::InvalidChannel);
        }
        let command = CtapHidCommand::from_wire(report[4])?;
        let expected_len = u16::from_be_bytes([report[5], report[6]]) as usize;
        if expected_len > MAX_PAYLOAD_SIZE {
            return Err(FrameError::PayloadTooLarge(expected_len));
        }
        let copy_len = expected_len.min(INIT_PAYLOAD_SIZE);
        let mut payload = Vec::with_capacity(expected_len);
        payload.extend_from_slice(&report[7..7 + copy_len]);
        Ok(Self {
            channel,
            command,
            expected_len,
            next_sequence: 0,
            payload,
        })
    }

    pub fn push_continuation(
        &mut self,
        report: &[u8],
    ) -> Result<Option<CtapHidMessage>, FrameError> {
        ensure_report(report)?;
        let channel = u32::from_be_bytes(report[0..4].try_into().expect("slice length"));
        if channel != self.channel {
            return Err(FrameError::InvalidChannel);
        }
        let sequence = report[4];
        if sequence != self.next_sequence {
            return Err(FrameError::InvalidSequence {
                expected: self.next_sequence,
                actual: sequence,
            });
        }
        self.next_sequence = self.next_sequence.wrapping_add(1);
        let remaining = self.expected_len.saturating_sub(self.payload.len());
        self.payload
            .extend_from_slice(&report[5..5 + remaining.min(CONTINUATION_PAYLOAD_SIZE)]);
        if self.payload.len() == self.expected_len {
            return Ok(Some(CtapHidMessage {
                channel: self.channel,
                command: self.command,
                payload: core::mem::take(&mut self.payload),
            }));
        }
        Ok(None)
    }
    #[must_use]
    pub const fn channel(&self) -> u32 {
        self.channel
    }
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.payload.len() == self.expected_len
    }
}

pub fn encode_initialization(
    channel: u32,
    command: CtapHidCommand,
    payload: &[u8],
) -> Result<[u8; HID_REPORT_SIZE], FrameError> {
    if channel == 0 {
        return Err(FrameError::InvalidChannel);
    }
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(FrameError::PayloadTooLarge(payload.len()));
    }
    let mut report = [0; HID_REPORT_SIZE];
    report[0..4].copy_from_slice(&channel.to_be_bytes());
    report[4] = command.wire();
    report[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    let copy_len = payload.len().min(INIT_PAYLOAD_SIZE);
    report[7..7 + copy_len].copy_from_slice(&payload[..copy_len]);
    Ok(report)
}

pub fn encode_continuations(
    channel: u32,
    payload: &[u8],
) -> Result<Vec<[u8; HID_REPORT_SIZE]>, FrameError> {
    if channel == 0 {
        return Err(FrameError::InvalidChannel);
    }
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(FrameError::PayloadTooLarge(payload.len()));
    }
    let mut reports = Vec::new();
    let mut offset = 0;
    let mut sequence = 0u8;
    while offset < payload.len() {
        let copy_len = (payload.len() - offset).min(CONTINUATION_PAYLOAD_SIZE);
        let mut report = [0; HID_REPORT_SIZE];
        report[0..4].copy_from_slice(&channel.to_be_bytes());
        report[4] = sequence;
        report[5..5 + copy_len].copy_from_slice(&payload[offset..offset + copy_len]);
        reports.push(report);
        offset += copy_len;
        sequence = sequence.wrapping_add(1);
    }
    Ok(reports)
}

fn ensure_report(report: &[u8]) -> Result<(), FrameError> {
    if report.len() == HID_REPORT_SIZE {
        Ok(())
    } else {
        Err(FrameError::InvalidReportLength(report.len()))
    }
}
