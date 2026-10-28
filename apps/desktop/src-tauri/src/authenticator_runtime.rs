use std::{
    sync::{
        Arc, Mutex,
        mpsc::{Receiver, TryRecvError, channel},
    },
    thread,
    time::{Duration, Instant},
};

use ghost_fido_core::{
    Ctap2Request, Ctap2Response, Ctap2Status, CtapHidCommand, GetInfoProfile, encode_initialization,
};
use ghost_platform::{
    AuthenticatorHidError, AuthenticatorHidEvent, AuthenticatorHidSession, AuthenticatorService,
    AuthenticatorServiceConfig, KeyCreationPolicy, KeyStore, PlatformErrorKind, SoftwareKeyConsent,
    UserVerification, VirtualHidBackend,
};

use crate::RuntimeStatus;

const CTAPHID_CHANNELS: usize = 16;
const CTAPHID_CHANNEL_TIMEOUT: Duration = Duration::from_secs(60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const IO_POLL_INTERVAL: Duration = Duration::from_millis(20);
const KEEPALIVE_INTERVAL: Duration = Duration::from_millis(100);
const KEEPALIVE_PROCESSING: u8 = 0x01;

enum ServiceCommand {
    Request { channel: u32, request: Ctap2Request },
    Cancel { channel: u32 },
    Stop,
}

struct ServiceResponse {
    channel: u32,
    response: Ctap2Response,
}

pub fn run(
    credential_store: Arc<Mutex<Option<ghost_fido_core::CredentialStore>>>,
    mut backend: Box<dyn VirtualHidBackend>,
    verification: Arc<dyn UserVerification>,
    status: Arc<Mutex<RuntimeStatus>>,
    stop: Receiver<()>,
    key_store: Box<dyn KeyStore>,
    key_creation_policy: KeyCreationPolicy,
    software_key_consent: Option<SoftwareKeyConsent>,
) {
    let Some(mut store) = credential_store
        .lock()
        .ok()
        .and_then(|mut store| store.take())
    else {
        set_runtime_failure(&status, "Credential storage is unavailable.");
        return;
    };

    if let Err(error) = backend.attach() {
        set_runtime_failure(&status, &error.detail);
        return_store(&credential_store, store);
        return;
    }

    set_runtime_status(
        &status,
        true,
        true,
        true,
        "Virtual authenticator is running.",
    );

    let (service_tx, service_rx) = channel();
    let (response_tx, response_rx) = channel();
    let service_verification = Arc::clone(&verification);
    let service_thread = thread::spawn(move || {
        let profile = GetInfoProfile {
            versions: vec!["FIDO_2_0".into()],
            aaguid: [0; 16],
            options: vec![
                ("rk".into(), true),
                ("up".into(), true),
                ("uv".into(), false),
                ("clientPin".into(), false),
                ("plat".into(), false),
            ],
            max_msg_size: 7609,
            pin_uv_auth_protocols: Vec::new(),
        };
        let config = AuthenticatorServiceConfig {
            get_info: profile,
            aaguid: [0; 16],
            key_creation_policy,
            software_key_consent,
            request_timeout: REQUEST_TIMEOUT,
        };
        let Ok(mut service) = AuthenticatorService::new(
            &mut store,
            &key_store,
            service_verification.as_ref(),
            config,
        ) else {
            return store;
        };

        while let Ok(command) = service_rx.recv() {
            match command {
                ServiceCommand::Request { channel, request } => {
                    let response =
                        service
                            .handle_on_channel(channel, &request)
                            .unwrap_or(Ctap2Response {
                                status: Ctap2Status::Other,
                                payload: Vec::new(),
                            });
                    if response_tx
                        .send(ServiceResponse { channel, response })
                        .is_err()
                    {
                        break;
                    }
                }
                ServiceCommand::Cancel { channel } => service.cancel_channel(channel),
                ServiceCommand::Stop => break,
            }
        }

        drop(service);
        store
    });

    let mut session = AuthenticatorHidSession::new(
        verification.as_ref(),
        CTAPHID_CHANNELS,
        CTAPHID_CHANNEL_TIMEOUT,
    );
    let mut active_request: Option<(u32, bool, Instant)> = None;
    let mut runtime_error = None;

    loop {
        match stop.try_recv() {
            Ok(()) | Err(TryRecvError::Disconnected) => break,
            Err(TryRecvError::Empty) => {}
        }

        match response_rx.try_recv() {
            Ok(response) => {
                if active_request.is_some_and(|(channel, _, _)| channel == response.channel) {
                    match session.respond_ctap2(response.channel, &response.response) {
                        Ok(reports) => {
                            if let Err(error) = send_reports(backend.as_mut(), &reports) {
                                runtime_error = Some(error.detail);
                                break;
                            }
                        }
                        Err(error) => runtime_error = Some(error.to_string()),
                    }
                    active_request = None;
                }
            }
            Err(TryRecvError::Disconnected) => {
                runtime_error = Some("Authenticator service stopped unexpectedly.".into());
                break;
            }
            Err(TryRecvError::Empty) => {}
        }

        match backend.receive_output_report(IO_POLL_INTERVAL) {
            Ok(report) => match session.receive_report(&report, Instant::now()) {
                Ok(AuthenticatorHidEvent::Reports(reports)) => {
                    if let Err(error) = send_reports(backend.as_mut(), &reports) {
                        runtime_error = Some(error.detail);
                        break;
                    }
                }
                Ok(AuthenticatorHidEvent::Ctap2Request { channel, request }) => {
                    if service_tx
                        .send(ServiceCommand::Request { channel, request })
                        .is_err()
                    {
                        runtime_error = Some("Authenticator service is unavailable.".into());
                        break;
                    }
                    active_request = Some((channel, false, Instant::now()));
                }
                Ok(AuthenticatorHidEvent::Cancelled(channel)) => {
                    if active_request
                        .is_some_and(|(active_channel, _, _)| active_channel == channel)
                    {
                        let _ = service_tx.send(ServiceCommand::Cancel { channel });
                        if let Some((_, cancelled, _)) = &mut active_request {
                            *cancelled = true;
                        }
                    }
                }
                Ok(AuthenticatorHidEvent::Pending | AuthenticatorHidEvent::Message(_)) => {}
                Err(AuthenticatorHidError::Framing(_)) => {}
            },
            Err(error) if error.kind == PlatformErrorKind::Timeout => {
                let now = Instant::now();
                for channel in session.expire(now) {
                    let _ = service_tx.send(ServiceCommand::Cancel { channel });
                    if active_request
                        .is_some_and(|(active_channel, _, _)| active_channel == channel)
                    {
                        active_request = None;
                    }
                }
            }
            Err(error) => {
                runtime_error = Some(error.detail);
                break;
            }
        }

        if let Some((channel, cancelled, last_keepalive)) = active_request {
            if !cancelled && last_keepalive.elapsed() >= KEEPALIVE_INTERVAL {
                match encode_initialization(
                    channel,
                    CtapHidCommand::Keepalive,
                    &[KEEPALIVE_PROCESSING],
                ) {
                    Ok(report) => {
                        if let Err(error) = backend.send_input_report(&report) {
                            runtime_error = Some(error.detail);
                            break;
                        }
                        if let Some((_, _, sent_at)) = &mut active_request {
                            *sent_at = Instant::now();
                        }
                    }
                    Err(error) => {
                        runtime_error = Some(error.to_string());
                        break;
                    }
                }
            }
        }
    }

    verification.cancel_pending();
    let _ = service_tx.send(ServiceCommand::Stop);
    let detach_error = backend.detach().err().map(|error| error.detail);
    let returned_store = service_thread.join().ok();
    if let Some(store) = returned_store {
        return_store(&credential_store, store);
    }

    let message = runtime_error
        .or(detach_error)
        .unwrap_or_else(|| "Virtual authenticator stopped.".into());
    set_runtime_status(
        &status,
        backend.availability().state == ghost_platform::CapabilityState::Available,
        false,
        false,
        &message,
    );
}

fn send_reports(
    backend: &mut dyn VirtualHidBackend,
    reports: &[[u8; ghost_fido_core::HID_REPORT_SIZE]],
) -> Result<(), ghost_platform::PlatformError> {
    for report in reports {
        backend.send_input_report(report)?;
    }
    Ok(())
}

fn return_store(
    credential_store: &Arc<Mutex<Option<ghost_fido_core::CredentialStore>>>,
    store: ghost_fido_core::CredentialStore,
) {
    if let Ok(mut slot) = credential_store.lock() {
        *slot = Some(store);
    }
}

fn set_runtime_failure(status: &Arc<Mutex<RuntimeStatus>>, message: &str) {
    set_runtime_status(status, false, false, false, message);
}

fn set_runtime_status(
    status: &Arc<Mutex<RuntimeStatus>>,
    available: bool,
    attached: bool,
    running: bool,
    message: &str,
) {
    if let Ok(mut status) = status.lock() {
        status.virtual_hid_available = available;
        status.device_attached = attached;
        status.authenticator_running = running;
        status.status_message = message.to_owned();
    }
}
