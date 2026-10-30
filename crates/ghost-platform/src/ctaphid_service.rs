//! Connects CTAPHID report sessions to the configured authenticator service.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use crate::UserVerification;
use ghost_fido_core::{
    Ctap2Response, CtapHidErrorCode, CtapHidSession, FrameError, HID_REPORT_SIZE, SessionEvent,
};

/// Owns CTAPHID transport state while leaving CTAP2 execution to its caller.
///
/// Separating request reception from execution lets the transport continue to
/// process cancellation and expiry while a CTAP2 command awaits user approval.
pub struct AuthenticatorHidSession<'verification> {
    hid: CtapHidSession,
    verification: &'verification dyn UserVerification,
    active_ctap2_requests: HashMap<u32, usize>,
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
            active_ctap2_requests: HashMap::new(),
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
                if self.processing_channel == Some(channel) {
                    self.verification.cancel_pending();
                    self.processing_channel = None;
                }
                SessionEvent::Cancelled(channel)
            }
            SessionEvent::Resynchronized { channel, response } => {
                self.active_ctap2_requests.remove(&channel);
                if self.processing_channel == Some(channel) {
                    self.verification.cancel_pending();
                    self.processing_channel = None;
                }
                SessionEvent::Resynchronized { channel, response }
            }
            SessionEvent::Ctap2Request { channel, request } => {
                let count = self.active_ctap2_requests.entry(channel).or_default();
                *count = count.saturating_add(1);
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
        let Some(count) = self.active_ctap2_requests.get_mut(&channel) else {
            return Ok(Vec::new());
        };
        let remove_channel = *count <= 1;
        if remove_channel {
            self.active_ctap2_requests.remove(&channel);
        } else {
            *count -= 1;
        }
        if self.processing_channel == Some(channel) {
            self.processing_channel = None;
        }
        self.hid.respond_ctap2_result(channel, response)
    }

    /// Rejects a completed request without disturbing another channel's request.
    pub fn reject_channel_busy(
        &mut self,
        channel: u32,
    ) -> Result<Vec<[u8; HID_REPORT_SIZE]>, FrameError> {
        let Some(count) = self.active_ctap2_requests.get_mut(&channel) else {
            return Ok(Vec::new());
        };
        if *count <= 1 {
            self.active_ctap2_requests.remove(&channel);
        } else {
            *count -= 1;
        }
        let report = self
            .hid
            .respond_error(channel, CtapHidErrorCode::ChannelBusy)?;
        Ok(vec![report])
    }

    /// Marks the channel currently executing in the serialized authenticator service.
    pub fn mark_processing(&mut self, channel: u32) {
        if self.active_ctap2_requests.contains_key(&channel) {
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
            self.active_ctap2_requests.remove(channel);
            if self.processing_channel == Some(*channel) {
                self.verification.cancel_pending();
                self.processing_channel = None;
            }
        }
    }
}
