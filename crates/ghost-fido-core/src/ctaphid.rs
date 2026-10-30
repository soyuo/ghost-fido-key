//! Transport-neutral CTAPHID report framing.

use crate::ctap2::{Ctap2Error, Ctap2Request, Ctap2Response, Ctap2Status, encode_response};
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
    InvalidSequence = 0x04,
    ChannelBusy = 0x06,
    InvalidChannel = 0x0b,
    Other = 0x7f,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtapHidDispatch {
    AllocateChannel,
    Resynchronize(Vec<u8>),
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
        CtapHidCommand::Init if channel_is_active && message.payload.len() == 8 => {
            Ok(CtapHidDispatch::Resynchronize(message.payload))
        }
        CtapHidCommand::Init => Err(CtapHidErrorCode::InvalidParameter),
        CtapHidCommand::Ping if message.channel != BROADCAST_CHANNEL && channel_is_active => {
            Ok(CtapHidDispatch::Ping(message.payload))
        }
        CtapHidCommand::Cbor if message.channel != BROADCAST_CHANNEL && channel_is_active => {
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
    InactiveChannel,
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
        let response = init_response_payload(nonce, channel);
        Ok((channel, response))
    }

    /// Refreshes an existing channel and returns the CTAPHID_INIT response
    /// payload used to abort and resynchronize an in-flight transaction.
    pub fn resynchronize(
        &mut self,
        channel: u32,
        nonce: &[u8],
        now: Instant,
        timeout: Duration,
    ) -> Result<[u8; INIT_RESPONSE_SIZE], ChannelError> {
        if nonce.len() != INIT_NONCE_SIZE {
            return Err(ChannelError::InvalidNonceLength(nonce.len()));
        }
        let deadline = self
            .active
            .get_mut(&channel)
            .ok_or(ChannelError::InactiveChannel)?;
        *deadline = now + timeout;
        Ok(init_response_payload(nonce, channel))
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

fn init_response_payload(nonce: &[u8], channel: u32) -> [u8; INIT_RESPONSE_SIZE] {
    let mut response = [0; INIT_RESPONSE_SIZE];
    response[..INIT_NONCE_SIZE].copy_from_slice(nonce);
    response[8..12].copy_from_slice(&channel.to_be_bytes());
    response[12..].copy_from_slice(&[2, 1, 0, 0, 0x04]);
    response
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
    transaction_channel: Option<u32>,
    channel_timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    Pending,
    Message(CtapHidDispatch),
    Ctap2Request {
        channel: u32,
        request: Ctap2Request,
    },
    Response([u8; HID_REPORT_SIZE]),
    Responses(Vec<[u8; HID_REPORT_SIZE]>),
    Cancelled(u32),
    Resynchronized {
        channel: u32,
        response: [u8; HID_REPORT_SIZE],
    },
}

impl CtapHidSession {
    #[must_use]
    pub fn new(channel_capacity: usize, channel_timeout: Duration) -> Self {
        Self {
            channels: CtapHidChannelAllocator::new(channel_capacity),
            pending: BTreeMap::new(),
            transaction_channel: None,
            channel_timeout,
        }
    }

    pub fn receive(&mut self, report: &[u8], now: Instant) -> Result<SessionEvent, FrameError> {
        self.expire(now);
        self.receive_unexpired(report, now)
    }

    /// Processes one report and also returns channel leases that expired first.
    /// This lets an adapter apply expiry side effects without running expiry twice.
    pub fn receive_with_expired(
        &mut self,
        report: &[u8],
        now: Instant,
    ) -> Result<(Vec<u32>, SessionEvent), FrameError> {
        let expired = self.expire(now);
        let event = self.receive_unexpired(report, now)?;
        Ok((expired, event))
    }

    fn receive_unexpired(
        &mut self,
        report: &[u8],
        now: Instant,
    ) -> Result<SessionEvent, FrameError> {
        ensure_report(report)?;
        let channel = u32::from_be_bytes(report[..4].try_into().expect("four bytes"));
        if channel == 0 {
            return Err(FrameError::InvalidChannel);
        }
        if report[4] & 0x80 == 0 {
            if !self.channels.is_active(channel) {
                return Ok(SessionEvent::Response(encode_error(
                    channel,
                    CtapHidErrorCode::InvalidChannel,
                )?));
            }
            let continuation = self
                .pending
                .get_mut(&channel)
                .ok_or(FrameError::UnexpectedContinuation)
                .and_then(|assembler| assembler.push_continuation(report));
            return match continuation {
                Ok(Some(message)) => {
                    self.pending.remove(&channel);
                    self.dispatch_and_release_immediate(message, now, true)
                }
                Ok(None) => Ok(SessionEvent::Pending),
                Err(error) => {
                    self.pending.remove(&channel);
                    if self.transaction_channel == Some(channel) {
                        self.transaction_channel = None;
                    }
                    Err(error)
                }
            };
        }

        let command = CtapHidCommand::from_wire(report[4])?;
        let is_broadcast_init = channel == BROADCAST_CHANNEL && command == CtapHidCommand::Init;
        if !is_broadcast_init && !self.channels.is_active(channel) {
            return Ok(SessionEvent::Response(encode_error(
                channel,
                CtapHidErrorCode::InvalidChannel,
            )?));
        }
        if !is_broadcast_init
            && self
                .transaction_channel
                .is_some_and(|active_channel| active_channel != channel)
        {
            return Ok(SessionEvent::Response(encode_error(
                channel,
                CtapHidErrorCode::ChannelBusy,
            )?));
        }
        let owns_transaction = self.transaction_channel.is_none();
        if self.pending.contains_key(&channel) {
            let payload_len = u16::from_be_bytes([report[5], report[6]]) as usize;
            if command == CtapHidCommand::Init
                && payload_len == INIT_NONCE_SIZE
                && self.channels.is_active(channel)
            {
                self.pending.remove(&channel);
            } else {
                return Ok(SessionEvent::Response(encode_error(
                    channel,
                    CtapHidErrorCode::InvalidSequence,
                )?));
            }
        }
        let message = CtapHidAssembler::start(report)?;
        if self.transaction_channel.is_none() {
            self.transaction_channel = Some(channel);
        }
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
        self.dispatch_and_release_immediate(complete, now, owns_transaction)
    }

    fn dispatch_and_release_immediate(
        &mut self,
        message: CtapHidMessage,
        now: Instant,
        owns_transaction: bool,
    ) -> Result<SessionEvent, FrameError> {
        let channel = message.channel;
        let event = self.dispatch_message(message, now)?;
        if owns_transaction
            && self.transaction_channel == Some(channel)
            && !matches!(&event, SessionEvent::Ctap2Request { .. })
        {
            self.transaction_channel = None;
        }
        Ok(event)
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
            Ok(CtapHidDispatch::Resynchronize(nonce)) => {
                let payload = self
                    .channels
                    .resynchronize(channel, &nonce, now, self.channel_timeout)
                    .map_err(|_| FrameError::InvalidChannel)?;
                let report = encode_initialization(channel, CtapHidCommand::Init, &payload)?;
                self.transaction_channel = None;
                Ok(SessionEvent::Resynchronized {
                    channel,
                    response: report,
                })
            }
            Ok(CtapHidDispatch::Ping(payload)) => {
                let first = encode_initialization(channel, CtapHidCommand::Ping, &payload)?;
                let mut reports = vec![first];
                reports.extend(encode_continuations(channel, &payload)?);
                if reports.len() == 1 {
                    Ok(SessionEvent::Response(first))
                } else {
                    Ok(SessionEvent::Responses(reports))
                }
            }
            Ok(CtapHidDispatch::Cancel) => Ok(SessionEvent::Cancelled(channel)),
            Ok(CtapHidDispatch::Cbor(payload)) => match Ctap2Request::decode(&payload) {
                Ok(request) => Ok(SessionEvent::Ctap2Request { channel, request }),
                Err(error) => {
                    let status = match error {
                        Ctap2Error::EmptyRequest | Ctap2Error::UnsupportedCommand(_) => {
                            Ctap2Status::InvalidCommand
                        }
                        Ctap2Error::InvalidCbor(_) => Ctap2Status::InvalidCbor,
                    };
                    let reports = encode_ctap2_response(channel, status, &[])?;
                    session_response(reports)
                }
            },
            Ok(action) => Ok(SessionEvent::Message(action)),
            Err(code) => Ok(SessionEvent::Response(encode_error(channel, code)?)),
        }
    }

    pub fn expire(&mut self, now: Instant) -> Vec<u32> {
        let expired = self.channels.expire(now);
        for channel in &expired {
            self.pending.remove(channel);
            if self.transaction_channel == Some(*channel) {
                self.transaction_channel = None;
            }
        }
        expired
    }

    /// Frames a CTAP2 result on its originating channel while it remains active.
    pub fn respond_ctap2(
        &mut self,
        channel: u32,
        status: Ctap2Status,
        payload: &[u8],
    ) -> Result<Vec<[u8; HID_REPORT_SIZE]>, FrameError> {
        if !self.channels.is_active(channel) {
            return Err(FrameError::InvalidChannel);
        }
        let reports = encode_ctap2_response(channel, status, payload)?;
        if self.transaction_channel == Some(channel) {
            self.transaction_channel = None;
        }
        Ok(reports)
    }

    /// Frames a CTAP2 handler result on its originating active channel.
    pub fn respond_ctap2_result(
        &mut self,
        channel: u32,
        response: &Ctap2Response,
    ) -> Result<Vec<[u8; HID_REPORT_SIZE]>, FrameError> {
        self.respond_ctap2(channel, response.status, &response.payload)
    }

    /// Frames a CTAPHID error for a completed request on its active channel.
    pub fn respond_error(
        &mut self,
        channel: u32,
        code: CtapHidErrorCode,
    ) -> Result<[u8; HID_REPORT_SIZE], FrameError> {
        if !self.channels.is_active(channel) {
            return Err(FrameError::InvalidChannel);
        }
        let report = encode_error(channel, code)?;
        if self.transaction_channel == Some(channel) {
            self.transaction_channel = None;
        }
        Ok(report)
    }
}

/// Adds the CTAP2 status byte and frames a response as CTAPHID CBOR reports.
pub fn encode_ctap2_response(
    channel: u32,
    status: Ctap2Status,
    payload: &[u8],
) -> Result<Vec<[u8; HID_REPORT_SIZE]>, FrameError> {
    let response = encode_response(status, payload);
    let first = encode_initialization(channel, CtapHidCommand::Cbor, &response)?;
    let mut reports = vec![first];
    reports.extend(encode_continuations(channel, &response)?);
    Ok(reports)
}

fn session_response(reports: Vec<[u8; HID_REPORT_SIZE]>) -> Result<SessionEvent, FrameError> {
    match reports.as_slice() {
        [report] => Ok(SessionEvent::Response(*report)),
        _ => Ok(SessionEvent::Responses(reports)),
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
