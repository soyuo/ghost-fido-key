//! Connects CTAPHID report sessions to the configured authenticator service.

use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

use crate::UserVerification;
use ghost_fido_core::{Ctap2Response, CtapHidSession, FrameError, HID_REPORT_SIZE, SessionEvent};

/// Owns CTAPHID transport state while leaving CTAP2 execution to its caller.
///
/// Separating request reception from execution lets the transport continue to
/// process cancellation and expiry while a CTAP2 command awaits user approval.
pub struct AuthenticatorHidSession<'verification> {
    hid: CtapHidSession,
    verification: &'verification dyn UserVerification,
    active_ctap2_channels: HashSet<u32>,
    processing_channel: Option<u32>,
}

impl<'verification> AuthenticatorHidSession<'verification> {
    #[must_use]
    pub fn new(
        verification: &'verification dyn UserVerification,
        channel_capacity: usize,
        channel_timeout: Duration,
    ) -> Self {
        Self {
            hid: CtapHidSession::new(channel_capacity, channel_timeout),
            verification,
            active_ctap2_channels: HashSet::new(),
            processing_channel: None,
        }
    }

    /// Accepts one output report and returns any input reports to send to the host.
    pub fn receive_report(
        &mut self,
        report: &[u8],
        now: Instant,
    ) -> Result<(Vec<u32>, SessionEvent), FrameError> {
        let (expired, event) = self.hid.receive_with_expired(report, now)?;
        self.handle_expired(&expired);
        let event = match event {
            event @ (SessionEvent::Pending
            | SessionEvent::Response(_)
            | SessionEvent::Responses(_)
            | SessionEvent::Message(_)) => event,
            SessionEvent::Cancelled(channel) => {
                self.active_ctap2_channels.remove(&channel);
                if self.processing_channel == Some(channel) {
                    self.verification.cancel_pending();
                    self.processing_channel = None;
                }
                SessionEvent::Cancelled(channel)
            }
            SessionEvent::Ctap2Request { channel, request } => {
                self.active_ctap2_channels.insert(channel);
                SessionEvent::Ctap2Request { channel, request }
            }
        };
        Ok((expired, event))
    }

    /// Frames a completed authenticator response on its still-active channel.
    pub fn respond_ctap2(
        &mut self,
        channel: u32,
        response: &Ctap2Response,
    ) -> Result<Vec<[u8; HID_REPORT_SIZE]>, FrameError> {
        if !self.active_ctap2_channels.remove(&channel) {
            return Ok(Vec::new());
        }
        if self.processing_channel == Some(channel) {
            self.processing_channel = None;
        }
        self.hid.respond_ctap2_result(channel, response)
    }

    /// Marks the channel currently executing in the serialized authenticator service.
    pub fn mark_processing(&mut self, channel: u32) {
        if self.active_ctap2_channels.contains(&channel) {
            self.processing_channel = Some(channel);
        }
    }

    /// Releases protocol and assertion state for channels whose CTAPHID lease expired.
    pub fn expire(&mut self, now: Instant) -> Vec<u32> {
        let expired = self.hid.expire(now);
        self.handle_expired(&expired);
        expired
    }

    fn handle_expired(&mut self, expired: &[u32]) {
        for channel in expired {
            self.active_ctap2_channels.remove(channel);
            if self.processing_channel == Some(*channel) {
                self.verification.cancel_pending();
                self.processing_channel = None;
            }
        }
    }
}
