//! Connects CTAPHID report sessions to the configured authenticator service.

use std::time::{Duration, Instant};

use ghost_fido_core::{CtapHidDispatch, CtapHidSession, FrameError, HID_REPORT_SIZE, SessionEvent};

use crate::{AuthenticatorService, AuthenticatorServiceError};

#[derive(Debug)]
pub enum AuthenticatorHidError {
    Framing(FrameError),
    Service(AuthenticatorServiceError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticatorHidEvent {
    Pending,
    Reports(Vec<[u8; HID_REPORT_SIZE]>),
    Cancelled(u32),
    Message(CtapHidDispatch),
}

/// Routes complete CTAPHID events through one authenticator and its channels.
pub struct AuthenticatorHidSession<'service, 'providers> {
    hid: CtapHidSession,
    service: &'service mut AuthenticatorService<'providers>,
}

impl<'service, 'providers> AuthenticatorHidSession<'service, 'providers> {
    #[must_use]
    pub fn new(
        service: &'service mut AuthenticatorService<'providers>,
        channel_capacity: usize,
        channel_timeout: Duration,
    ) -> Self {
        Self {
            hid: CtapHidSession::new(channel_capacity, channel_timeout),
            service,
        }
    }

    /// Accepts one output report and returns any input reports to send to the host.
    pub fn receive_report(
        &mut self,
        report: &[u8],
        now: Instant,
    ) -> Result<AuthenticatorHidEvent, AuthenticatorHidError> {
        self.expire(now);
        let event = self
            .hid
            .receive(report, now)
            .map_err(AuthenticatorHidError::Framing)?;
        match event {
            SessionEvent::Pending => Ok(AuthenticatorHidEvent::Pending),
            SessionEvent::Response(report) => Ok(AuthenticatorHidEvent::Reports(vec![report])),
            SessionEvent::Responses(reports) => Ok(AuthenticatorHidEvent::Reports(reports)),
            SessionEvent::Cancelled(channel) => {
                self.service.clear_channel(channel);
                Ok(AuthenticatorHidEvent::Cancelled(channel))
            }
            SessionEvent::Message(message) => Ok(AuthenticatorHidEvent::Message(message)),
            SessionEvent::Ctap2Request { channel, request } => {
                let response = self
                    .service
                    .handle_on_channel(channel, &request)
                    .map_err(AuthenticatorHidError::Service)?;
                let reports = self
                    .hid
                    .respond_ctap2_result(channel, &response)
                    .map_err(AuthenticatorHidError::Framing)?;
                Ok(AuthenticatorHidEvent::Reports(reports))
            }
        }
    }

    /// Releases protocol and assertion state for channels whose CTAPHID lease expired.
    pub fn expire(&mut self, now: Instant) -> Vec<u32> {
        let expired = self.hid.expire(now);
        for channel in &expired {
            self.service.clear_channel(*channel);
        }
        expired
    }
}
