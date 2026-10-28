//! Transport-neutral CTAPHID report framing.

use core::fmt;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

pub const HID_REPORT_SIZE: usize = 64;
pub const INIT_PAYLOAD_SIZE: usize = HID_REPORT_SIZE - 7;
pub const CONTINUATION_PAYLOAD_SIZE: usize = HID_REPORT_SIZE - 5;
pub const MAX_PAYLOAD_SIZE: usize = 7609;
pub const BROADCAST_CHANNEL: u32 = 0xffff_ffff;
pub const INIT_NONCE_SIZE: usize = 8;
pub const INIT_RESPONSE_SIZE: usize = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtapHidErrorCode {
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    ChannelBusy = 0x06,
    InvalidChannel = 0x0b,
    Other = 0x7f,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtapHidDispatch {
    AllocateChannel,
    Ping(Vec<u8>),
    Cbor(Vec<u8>),
    Cancel,
    Unsupported,
}

/// Validates a complete message and maps supported commands to core actions.
/// INIT allocation policy and CBOR execution remain with their owning layers.
pub fn dispatch(
    message: CtapHidMessage,
    channel_is_active: bool,
) -> Result<CtapHidDispatch, CtapHidErrorCode> {
    match message.command {
        CtapHidCommand::Init
            if message.channel == BROADCAST_CHANNEL && message.payload.len() == 8 =>
        {
            Ok(CtapHidDispatch::AllocateChannel)
        }
        CtapHidCommand::Init => Err(CtapHidErrorCode::InvalidParameter),
        CtapHidCommand::Ping if message.channel != BROADCAST_CHANNEL && channel_is_active => {
            Ok(CtapHidDispatch::Ping(message.payload))
        }
        CtapHidCommand::Cbor
            if message.channel != BROADCAST_CHANNEL
                && channel_is_active
                && !message.payload.is_empty() =>
        {
            Ok(CtapHidDispatch::Cbor(message.payload))
        }
        CtapHidCommand::Cancel
            if message.channel != BROADCAST_CHANNEL
                && channel_is_active
                && message.payload.is_empty() =>
        {
            Ok(CtapHidDispatch::Cancel)
        }
        CtapHidCommand::Ping | CtapHidCommand::Cbor | CtapHidCommand::Cancel
            if message.channel == BROADCAST_CHANNEL =>
        {
            Err(CtapHidErrorCode::InvalidChannel)
        }
        CtapHidCommand::Ping | CtapHidCommand::Cbor | CtapHidCommand::Cancel
            if !channel_is_active =>
        {
            Err(CtapHidErrorCode::InvalidChannel)
        }
        CtapHidCommand::Cbor if message.payload.is_empty() => Err(CtapHidErrorCode::InvalidLength),
        CtapHidCommand::Keepalive | CtapHidCommand::Error => Err(CtapHidErrorCode::InvalidCommand),
        _ => Ok(CtapHidDispatch::Unsupported),
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelError {
    Exhausted,
    InvalidNonceLength(usize),
}

/// Tracks concurrent CTAPHID channels and their deadlines without choosing an
/// executor or timer implementation for the platform layer.
#[derive(Debug)]
pub struct CtapHidChannelAllocator {
    capacity: usize,
    next_candidate: u32,
    active: BTreeMap<u32, Instant>,
}

impl CtapHidChannelAllocator {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            next_candidate: 1,
            active: BTreeMap::new(),
        }
    }

    pub fn allocate(&mut self, now: Instant, timeout: Duration) -> Result<u32, ChannelError> {
        self.expire(now);
        if self.active.len() >= self.capacity {
            return Err(ChannelError::Exhausted);
        }
        for _ in 0..=self.capacity.saturating_add(1) {
            let candidate = self.next_candidate;
            self.next_candidate = self.next_candidate.wrapping_add(1).max(1);
            if candidate != BROADCAST_CHANNEL
                && candidate != 0
                && !self.active.contains_key(&candidate)
            {
                self.active.insert(candidate, now + timeout);
                return Ok(candidate);
            }
        }
        Err(ChannelError::Exhausted)
    }

    /// Allocates a channel for a valid broadcast INIT request and returns the
    /// CTAPHID_INIT response payload (nonce, channel, protocol, version, caps).
    pub fn initialize(
        &mut self,
        nonce: &[u8],
        now: Instant,
        timeout: Duration,
    ) -> Result<(u32, [u8; INIT_RESPONSE_SIZE]), ChannelError> {
        if nonce.len() != INIT_NONCE_SIZE {
            return Err(ChannelError::InvalidNonceLength(nonce.len()));
        }
        let channel = self.allocate(now, timeout)?;
        let mut response = [0; INIT_RESPONSE_SIZE];
        response[..INIT_NONCE_SIZE].copy_from_slice(nonce);
        response[8..12].copy_from_slice(&channel.to_be_bytes());
        response[12..].copy_from_slice(&[2, 1, 0, 0, 0]);
        Ok((channel, response))
    }

    pub fn release(&mut self, channel: u32) -> bool {
        self.active.remove(&channel).is_some()
    }

    pub fn expire(&mut self, now: Instant) -> Vec<u32> {
        let expired: Vec<u32> = self
            .active
            .iter()
            .filter_map(|(&channel, &deadline)| (deadline <= now).then_some(channel))
            .collect();
        for channel in &expired {
            self.active.remove(channel);
        }
        expired
    }

    #[must_use]
    pub fn is_active(&self, channel: u32) -> bool {
        self.active.contains_key(&channel)
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }
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

/// Encodes a CTAPHID_ERROR command report using the supplied channel.
pub fn encode_error(
    channel: u32,
    code: CtapHidErrorCode,
) -> Result<[u8; HID_REPORT_SIZE], FrameError> {
    encode_initialization(channel, CtapHidCommand::Error, &[code as u8])
}

/// Owns in-flight fragmented messages and initialized channels for one HID
/// transport instance. Platform code supplies time and handles returned actions.
#[derive(Debug)]
pub struct CtapHidSession {
    channels: CtapHidChannelAllocator,
    pending: BTreeMap<u32, CtapHidAssembler>,
    channel_timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    Pending,
    Message(CtapHidDispatch),
    Response([u8; HID_REPORT_SIZE]),
    Cancelled(u32),
}

impl CtapHidSession {
    #[must_use]
    pub fn new(channel_capacity: usize, channel_timeout: Duration) -> Self {
        Self {
            channels: CtapHidChannelAllocator::new(channel_capacity),
            pending: BTreeMap::new(),
            channel_timeout,
        }
    }

    pub fn receive(&mut self, report: &[u8], now: Instant) -> Result<SessionEvent, FrameError> {
        self.expire(now);
        let channel = if report.len() == HID_REPORT_SIZE {
            u32::from_be_bytes(report[..4].try_into().expect("four bytes"))
        } else {
            return Err(FrameError::InvalidReportLength(report.len()));
        };
        if report[4] & 0x80 == 0 {
            let assembler = self
                .pending
                .get_mut(&channel)
                .ok_or(FrameError::UnexpectedContinuation)?;
            return match assembler.push_continuation(report)? {
                Some(message) => {
                    self.pending.remove(&channel);
                    self.dispatch_message(message, now)
                }
                None => Ok(SessionEvent::Pending),
            };
        }
        let message = CtapHidAssembler::start(report)?;
        if !message.is_complete() {
            self.pending.insert(channel, message);
            return Ok(SessionEvent::Pending);
        }
        let mut message = message;
        let complete = CtapHidMessage {
            channel: message.channel,
            command: message.command,
            payload: core::mem::take(&mut message.payload),
        };
        self.dispatch_message(complete, now)
    }

    fn dispatch_message(
        &mut self,
        message: CtapHidMessage,
        now: Instant,
    ) -> Result<SessionEvent, FrameError> {
        let channel = message.channel;
        let active = self.channels.is_active(channel);
        match dispatch(message.clone(), active) {
            Ok(CtapHidDispatch::AllocateChannel) => {
                let (assigned, payload) = self
                    .channels
                    .initialize(&message.payload, now, self.channel_timeout)
                    .map_err(|_| FrameError::InvalidChannel)?;
                let report = encode_initialization(assigned, CtapHidCommand::Init, &payload)?;
                Ok(SessionEvent::Response(report))
            }
            Ok(CtapHidDispatch::Cancel) => Ok(SessionEvent::Cancelled(channel)),
            Ok(action) => Ok(SessionEvent::Message(action)),
            Err(code) => Ok(SessionEvent::Response(encode_error(channel, code)?)),
        }
    }

    pub fn expire(&mut self, now: Instant) -> Vec<u32> {
        let expired = self.channels.expire(now);
        for channel in &expired {
            self.pending.remove(channel);
        }
        expired
    }
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
