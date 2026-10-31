use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::Sender,
        mpsc::{Receiver, TryRecvError, channel},
    },
    thread,
    time::{Duration, Instant},
};

use ghost_fido_core::{
    Ctap2Request, Ctap2Response, Ctap2Status, CtapHidCommand, GetInfoProfile, SessionEvent,
    encode_initialization,
};
use ghost_platform::{
    AuthenticatorHidSession, AuthenticatorService, AuthenticatorServiceConfig, KeyCreationPolicy,
    KeyStore, PlatformErrorKind, SoftwareKeyConsent, UserVerification, VirtualHidBackend,
};

use crate::{RuntimeStatus, audit};

const CTAPHID_CHANNELS: usize = 16;
const CTAPHID_CHANNEL_TIMEOUT: Duration = Duration::from_secs(60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const IO_POLL_INTERVAL: Duration = Duration::from_millis(20);
const KEEPALIVE_INTERVAL: Duration = Duration::from_millis(100);
const KEEPALIVE_PROCESSING: u8 = 0x01;

enum ServiceCommand {
    Request {
        request_id: u64,
        channel: u32,
        request: Ctap2Request,
    },
    Cancel {
        channel: u32,
    },
    Stop,
}

struct ServiceResponse {
    request_id: u64,
    channel: u32,
    response: Ctap2Response,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RequestDisposition {
    KeepaliveCancel,
    Discard,
}

struct PendingRequest {
    channel: u32,
    disposition: Option<RequestDisposition>,
    last_keepalive: Instant,
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
    client_pin_configured: Arc<AtomicBool>,
    reset_pending: Arc<AtomicBool>,
    provider_key_cleanup_pending: Arc<AtomicBool>,
) {
    let Some(mut store) = credential_store
        .lock()
        .ok()
        .and_then(|mut store| store.take())
    else {
        let availability = backend.availability();
        set_runtime_failure(
            &status,
            availability.state == ghost_platform::CapabilityState::Available,
            availability.can_start(),
            "Credential storage is unavailable.",
        );
        return;
    };
    reset_pending.store(store.reset_is_pending(), Ordering::Release);
    provider_key_cleanup_pending.store(store.provider_key_cleanup_pending(), Ordering::Release);

    if let Err(error) = backend.attach() {
        let availability = backend.availability();
        set_runtime_failure(
            &status,
            availability.state == ghost_platform::CapabilityState::Available,
            availability.can_start(),
            &error.detail,
        );
        return_store(&credential_store, store);
        return;
    }

    let availability = backend.availability();
    set_runtime_status(
        &status,
        availability.state == ghost_platform::CapabilityState::Available,
        availability.can_start(),
        true,
        true,
        "Virtual authenticator is running.",
    );
    audit::record(audit::Event::RuntimeStarted, audit::Outcome::Success);

    let (service_tx, service_rx) = channel();
    let (response_tx, response_rx) = channel();
    let service_verification = Arc::clone(&verification);
    let service_thread = thread::spawn(move || {
        let profile = GetInfoProfile {
            versions: vec!["FIDO_2_0".into()],
            extensions: Vec::new(),
            aaguid: [0; 16],
            options: vec![
                ("rk".into(), true),
                ("up".into(), true),
                ("clientPin".into(), false),
                ("plat".into(), false),
            ],
            max_msg_size: 7609,
            pin_uv_auth_protocols: Vec::new(),
            force_pin_change: false,
            min_pin_length: None,
            max_rp_ids_for_set_min_pin_length: None,
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
            key_store.as_ref(),
            service_verification.as_ref(),
            config,
        ) else {
            return store;
        };

        while let Ok(command) = service_rx.recv() {
            match command {
                ServiceCommand::Request {
                    request_id,
                    channel,
                    request,
                } => {
                    let response =
                        service
                            .handle_on_channel(channel, request)
                            .unwrap_or(Ctap2Response {
                                status: Ctap2Status::Other,
                                payload: Vec::new(),
                            });
                    client_pin_configured
                        .store(service.client_pin_is_configured(), Ordering::Release);
                    reset_pending.store(service.reset_is_pending(), Ordering::Release);
                    provider_key_cleanup_pending
                        .store(service.provider_key_cleanup_is_pending(), Ordering::Release);
                    if response_tx
                        .send(ServiceResponse {
                            request_id,
                            channel,
                            response,
                        })
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
    let mut active_service_request: Option<u64> = None;
    let mut next_request_id = 0u64;
    let mut pending_requests: HashMap<u64, PendingRequest> = HashMap::new();
    let mut latest_request_by_channel: HashMap<u32, u64> = HashMap::new();
    let mut queued_requests = VecDeque::new();
    let mut runtime_error = None;

    'runtime: loop {
        match stop.try_recv() {
            Ok(()) | Err(TryRecvError::Disconnected) => break,
            Err(TryRecvError::Empty) => {}
        }

        match response_rx.try_recv() {
            Ok(response) => {
                if active_service_request == Some(response.request_id) {
                    active_service_request = None;
                    if let Some(request) = remove_pending_request(
                        response.request_id,
                        &mut pending_requests,
                        &mut latest_request_by_channel,
                    ) {
                        let completed_response = match request.disposition {
                            None => Some(response.response),
                            Some(RequestDisposition::KeepaliveCancel) => Some(Ctap2Response {
                                status: Ctap2Status::KeepaliveCancel,
                                payload: Vec::new(),
                            }),
                            Some(RequestDisposition::Discard) => None,
                        };
                        if request.channel == response.channel {
                            if let Some(completed_response) = completed_response {
                                match session.respond_ctap2(request.channel, &completed_response) {
                                    Ok(reports) => {
                                        if let Err(error) = send_reports(backend.as_mut(), &reports)
                                        {
                                            runtime_error = Some(error.detail);
                                            break;
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
                    if let Err(error) = dispatch_next_request(
                        &service_tx,
                        &mut queued_requests,
                        &mut pending_requests,
                        &mut latest_request_by_channel,
                        &mut active_service_request,
                        &mut session,
                        backend.as_mut(),
                    ) {
                        runtime_error = Some(error);
                        break;
                    }
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
                Ok((expired, event)) => {
                    handle_expired_channels(
                        expired,
                        &service_tx,
                        &mut queued_requests,
                        &mut pending_requests,
                        &mut latest_request_by_channel,
                        active_service_request,
                    );
                    match event {
                        SessionEvent::Response(report) => {
                            if let Err(error) =
                                send_reports(backend.as_mut(), std::slice::from_ref(&report))
                            {
                                runtime_error = Some(error.detail);
                                break;
                            }
                        }
                        SessionEvent::Responses(reports) => {
                            if let Err(error) = send_reports(backend.as_mut(), &reports) {
                                runtime_error = Some(error.detail);
                                break;
                            }
                        }
                        SessionEvent::Ctap2Request { channel, request } => {
                            let service_busy_on_other_channel = active_service_request
                                .and_then(|request_id| pending_requests.get(&request_id))
                                .is_some_and(|active| active.channel != channel);
                            if service_busy_on_other_channel {
                                match session.reject_channel_busy(channel) {
                                    Ok(reports) => {
                                        if let Err(error) = send_reports(backend.as_mut(), &reports)
                                        {
                                            runtime_error = Some(error.detail);
                                            break;
                                        }
                                    }
                                    Err(error) => {
                                        runtime_error = Some(error.to_string());
                                        break;
                                    }
                                }
                            } else {
                                if pending_requests.len() >= CTAPHID_CHANNELS {
                                    runtime_error = Some("CTAPHID request queue is full.".into());
                                    break;
                                }
                                let request_id =
                                    allocate_request_id(&mut next_request_id, &pending_requests);
                                pending_requests.insert(
                                    request_id,
                                    PendingRequest {
                                        channel,
                                        disposition: None,
                                        last_keepalive: Instant::now(),
                                    },
                                );
                                latest_request_by_channel.insert(channel, request_id);
                                queued_requests.push_back((request_id, channel, request));
                                if active_service_request.is_none() {
                                    if let Err(error) = dispatch_next_request(
                                        &service_tx,
                                        &mut queued_requests,
                                        &mut pending_requests,
                                        &mut latest_request_by_channel,
                                        &mut active_service_request,
                                        &mut session,
                                        backend.as_mut(),
                                    ) {
                                        runtime_error = Some(error);
                                        break;
                                    }
                                }
                            }
                        }
                        SessionEvent::Cancelled(channel) => {
                            let active_on_channel = active_service_request.filter(|request_id| {
                                pending_requests
                                    .get(request_id)
                                    .is_some_and(|request| request.channel == channel)
                            });
                            let latest_request = latest_request_by_channel.get(&channel).copied();
                            let request_id = active_on_channel
                                .filter(|request_id| {
                                    pending_requests
                                        .get(request_id)
                                        .is_some_and(|request| request.disposition.is_none())
                                })
                                .or(latest_request);
                            if let Some(request_id) = request_id {
                                if let Some(request) = pending_requests.get_mut(&request_id) {
                                    request.disposition = Some(RequestDisposition::KeepaliveCancel);
                                }
                            }
                            if active_on_channel.is_some() {
                                let _ = service_tx.send(ServiceCommand::Cancel { channel });
                            }
                        }
                        SessionEvent::Resynchronized { channel, response } => {
                            abort_channel_requests(
                                channel,
                                RequestDisposition::Discard,
                                &service_tx,
                                &mut queued_requests,
                                &mut pending_requests,
                                &mut latest_request_by_channel,
                                active_service_request,
                            );
                            if let Err(error) =
                                send_reports(backend.as_mut(), std::slice::from_ref(&response))
                            {
                                runtime_error = Some(error.detail);
                                break;
                            }
                        }
                        SessionEvent::Pending | SessionEvent::Message(_) => {}
                    }
                }
                Err(_) => {}
            },
            Err(error) if error.kind == PlatformErrorKind::Timeout => {
                let now = Instant::now();
                handle_expired_channels(
                    session.expire(now),
                    &service_tx,
                    &mut queued_requests,
                    &mut pending_requests,
                    &mut latest_request_by_channel,
                    active_service_request,
                );
            }
            Err(error) => {
                runtime_error = Some(error.detail);
                break;
            }
        }

        for request in pending_requests.values_mut() {
            if request.disposition.is_none()
                && request.last_keepalive.elapsed() >= KEEPALIVE_INTERVAL
            {
                match encode_initialization(
                    request.channel,
                    CtapHidCommand::Keepalive,
                    &[KEEPALIVE_PROCESSING],
                ) {
                    Ok(report) => {
                        if let Err(error) = backend.send_input_report(&report) {
                            runtime_error = Some(error.detail);
                            break 'runtime;
                        }
                        request.last_keepalive = Instant::now();
                    }
                    Err(error) => {
                        runtime_error = Some(error.to_string());
                        break 'runtime;
                    }
                }
            }
        }
    }

    verification.cancel_pending();
    let _ = service_tx.send(ServiceCommand::Stop);
    let detach_error = backend.detach().err().map(|error| error.detail);
    let service_error = match service_thread.join() {
        Ok(store) => {
            return_store(&credential_store, store);
            None
        }
        Err(_) => Some("Authenticator service failed unexpectedly.".to_owned()),
    };
    let outcome = if runtime_error.is_some() || service_error.is_some() || detach_error.is_some() {
        audit::Outcome::Failure
    } else {
        audit::Outcome::Success
    };
    audit::record(audit::Event::RuntimeStopped, outcome);

    let message = runtime_error
        .or(service_error)
        .or(detach_error)
        .unwrap_or_else(|| "Virtual authenticator stopped.".into());
    set_runtime_status(
        &status,
        backend.availability().state == ghost_platform::CapabilityState::Available,
        backend.availability().can_start(),
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

fn allocate_request_id(
    next_request_id: &mut u64,
    pending_requests: &HashMap<u64, PendingRequest>,
) -> u64 {
    loop {
        let request_id = *next_request_id;
        *next_request_id = (*next_request_id).wrapping_add(1);
        if !pending_requests.contains_key(&request_id) {
            return request_id;
        }
    }
}

fn remove_pending_request(
    request_id: u64,
    pending_requests: &mut HashMap<u64, PendingRequest>,
    latest_request_by_channel: &mut HashMap<u32, u64>,
) -> Option<PendingRequest> {
    let request = pending_requests.remove(&request_id)?;
    if latest_request_by_channel.get(&request.channel) == Some(&request_id) {
        if let Some(latest_request_id) = pending_requests
            .keys()
            .filter(|candidate| {
                pending_requests
                    .get(candidate)
                    .is_some_and(|pending| pending.channel == request.channel)
            })
            .copied()
            .max()
        {
            latest_request_by_channel.insert(request.channel, latest_request_id);
        } else {
            latest_request_by_channel.remove(&request.channel);
        }
    }
    Some(request)
}

fn abort_channel_requests(
    channel: u32,
    disposition: RequestDisposition,
    service: &Sender<ServiceCommand>,
    queued_requests: &mut VecDeque<(u64, u32, Ctap2Request)>,
    pending_requests: &mut HashMap<u64, PendingRequest>,
    latest_request_by_channel: &mut HashMap<u32, u64>,
    active_service_request: Option<u64>,
) {
    if let Some(request_id) = active_service_request.filter(|request_id| {
        pending_requests
            .get(request_id)
            .is_some_and(|request| request.channel == channel)
    }) {
        if let Some(request) = pending_requests.get_mut(&request_id) {
            request.disposition = Some(disposition);
        }
        let _ = service.send(ServiceCommand::Cancel { channel });
    }

    let mut queued_to_remove = Vec::new();
    queued_requests.retain(|(request_id, request_channel, _)| {
        if *request_channel == channel {
            queued_to_remove.push(*request_id);
            false
        } else {
            true
        }
    });
    for request_id in queued_to_remove {
        remove_pending_request(request_id, pending_requests, latest_request_by_channel);
    }
    latest_request_by_channel.remove(&channel);
}

fn handle_expired_channels(
    expired: Vec<u32>,
    service: &Sender<ServiceCommand>,
    queued_requests: &mut VecDeque<(u64, u32, Ctap2Request)>,
    pending_requests: &mut HashMap<u64, PendingRequest>,
    latest_request_by_channel: &mut HashMap<u32, u64>,
    active_service_request: Option<u64>,
) {
    for channel in expired {
        abort_channel_requests(
            channel,
            RequestDisposition::Discard,
            service,
            queued_requests,
            pending_requests,
            latest_request_by_channel,
            active_service_request,
        );
    }
}

fn dispatch_next_request(
    service: &Sender<ServiceCommand>,
    queued_requests: &mut VecDeque<(u64, u32, Ctap2Request)>,
    pending_requests: &mut HashMap<u64, PendingRequest>,
    latest_request_by_channel: &mut HashMap<u32, u64>,
    active_service_request: &mut Option<u64>,
    session: &mut AuthenticatorHidSession<'_>,
    backend: &mut dyn VirtualHidBackend,
) -> Result<(), String> {
    if active_service_request.is_some() {
        return Ok(());
    }
    while let Some((request_id, channel, request)) = queued_requests.pop_front() {
        let Some(pending) = pending_requests.get(&request_id) else {
            continue;
        };
        match pending.disposition {
            Some(RequestDisposition::Discard) => {
                remove_pending_request(request_id, pending_requests, latest_request_by_channel);
                continue;
            }
            Some(RequestDisposition::KeepaliveCancel) => {
                let response = Ctap2Response {
                    status: Ctap2Status::KeepaliveCancel,
                    payload: Vec::new(),
                };
                let reports = session
                    .respond_ctap2(channel, &response)
                    .map_err(|error| error.to_string())?;
                send_reports(backend, &reports).map_err(|error| error.detail)?;
                remove_pending_request(request_id, pending_requests, latest_request_by_channel);
                continue;
            }
            None => {}
        }
        service
            .send(ServiceCommand::Request {
                request_id,
                channel,
                request,
            })
            .map_err(|_| "Authenticator service is unavailable.".to_owned())?;
        *active_service_request = Some(request_id);
        session.mark_processing(channel);
        break;
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

fn set_runtime_failure(
    status: &Arc<Mutex<RuntimeStatus>>,
    available: bool,
    can_start: bool,
    message: &str,
) {
    audit::record(audit::Event::RuntimeFailure, audit::Outcome::Failure);
    set_runtime_status(status, available, can_start, false, false, message);
}

fn set_runtime_status(
    status: &Arc<Mutex<RuntimeStatus>>,
    available: bool,
    can_start: bool,
    attached: bool,
    running: bool,
    message: &str,
) {
    if let Ok(mut status) = status.lock() {
        status.virtual_hid_available = available;
        status.virtual_hid_can_start = can_start;
        status.device_attached = attached;
        status.authenticator_running = running;
        status.status_message = message.to_owned();
    }
}
