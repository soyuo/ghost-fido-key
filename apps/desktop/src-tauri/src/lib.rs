use ghost_fido_core::{
    CredentialProtector, CredentialStore, PIN_MAX_UTF8_BYTES, PinManagementError, ProductInfo,
    configure_client_pin,
};
use ghost_platform::KeyReference;
#[cfg(target_os = "linux")]
use ghost_platform::LinuxKeyStore;
#[cfg(target_os = "macos")]
use ghost_platform::MacOsKeyStore;
#[cfg(target_os = "windows")]
use ghost_platform::WindowsKeyStore;
use ghost_platform::{
    CapabilityState, HostPlatform, PlatformError, PlatformErrorKind, UserVerification,
    VerificationAction, VerificationDecision, VerificationRequest,
};
use ghost_platform::{KeyCreationPolicy, KeyStore, SoftwareKeyConsent};
use serde::Serialize;
use std::collections::HashMap;
use std::{
    fs,
    sync::{Arc, Mutex, mpsc, mpsc::SyncSender},
    thread::JoinHandle,
    time::Duration,
};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use uuid::Uuid;
use zeroize::Zeroizing;

struct DesktopState {
    credential_store: Arc<Mutex<Option<CredentialStore>>>,
    credential_store_available: bool,
    credential_store_status: String,
    verification: Arc<DesktopVerificationProvider>,
    virtual_hid: Arc<Mutex<RuntimeStatus>>,
    runtime: Mutex<Option<RuntimeHandle>>,
}

struct RuntimeHandle {
    stop: SyncSender<()>,
    worker: JoinHandle<()>,
}

#[derive(Default)]
struct RuntimeStatus {
    virtual_hid_available: bool,
    device_attached: bool,
    authenticator_running: bool,
    key_storage_status: String,
    status_message: String,
}

struct DesktopVerificationProvider {
    app: AppHandle,
    pending: Mutex<HashMap<String, PendingApproval>>,
}

struct PendingApproval {
    sender: SyncSender<VerificationDecision>,
    relying_party_id: String,
    relying_party_name: Option<String>,
    action: &'static str,
    responding: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalPrompt {
    request_id: String,
    relying_party_id: String,
    relying_party_name: Option<String>,
    action: &'static str,
    timeout_millis: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PlatformStatus {
    product_name: &'static str,
    product_version: &'static str,
    host_platform: &'static str,
    virtual_hid_available: bool,
    device_attached: bool,
    key_storage_status: String,
    desktop_approval_status: &'static str,
    client_pin_status: &'static str,
    native_user_verification_status: &'static str,
    credential_store_available: bool,
    credential_store_status: String,
    status_message: String,
    authenticator_running: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CredentialSummary {
    creation_order: u64,
    relying_party_id: Option<String>,
    user_name: Option<String>,
    user_display_name: Option<String>,
    key_protection: &'static str,
    exportable: bool,
    discoverable: bool,
}

#[cfg(target_os = "windows")]
fn credential_protector() -> Option<Arc<dyn CredentialProtector>> {
    Some(Arc::new(ghost_platform::WindowsCredentialProtector))
}

#[cfg(target_os = "linux")]
fn credential_protector() -> Option<Arc<dyn CredentialProtector>> {
    Some(Arc::new(ghost_platform::LinuxCredentialProtector::new()))
}

#[cfg(target_os = "macos")]
fn credential_protector() -> Option<Arc<dyn CredentialProtector>> {
    Some(Arc::new(ghost_platform::MacOsCredentialProtector::new()))
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn credential_protector() -> Option<Arc<dyn CredentialProtector>> {
    None
}

#[cfg(target_os = "linux")]
fn runtime_key_provider(
    software_key_risk_acknowledged: bool,
) -> Result<
    (
        Box<dyn KeyStore>,
        KeyCreationPolicy,
        Option<SoftwareKeyConsent>,
    ),
    String,
> {
    let consent = SoftwareKeyConsent::confirm_user_acceptance(software_key_risk_acknowledged)
        .ok_or("Explicit acceptance of the software-key warning is required.")?;
    Ok((
        Box::new(LinuxKeyStore::new()),
        KeyCreationPolicy::SoftwareKeyAfterExplicitConsent,
        Some(consent),
    ))
}

#[cfg(target_os = "linux")]
fn management_key_store() -> Result<Box<dyn KeyStore>, String> {
    Ok(Box::new(LinuxKeyStore::new()))
}

#[cfg(target_os = "windows")]
fn management_key_store() -> Result<Box<dyn KeyStore>, String> {
    Ok(Box::new(WindowsKeyStore::new()))
}

#[cfg(target_os = "macos")]
fn management_key_store() -> Result<Box<dyn KeyStore>, String> {
    Ok(Box::new(MacOsKeyStore::new()))
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn management_key_store() -> Result<Box<dyn KeyStore>, String> {
    Err("Credential key management is unsupported on this operating system.".into())
}

#[cfg(target_os = "windows")]
fn runtime_key_provider(
    _software_key_risk_acknowledged: bool,
) -> Result<
    (
        Box<dyn KeyStore>,
        KeyCreationPolicy,
        Option<SoftwareKeyConsent>,
    ),
    String,
> {
    Ok((
        Box::new(WindowsKeyStore::new()),
        KeyCreationPolicy::PlatformProtectedOnly,
        None,
    ))
}

#[cfg(target_os = "macos")]
fn runtime_key_provider(
    _software_key_risk_acknowledged: bool,
) -> Result<
    (
        Box<dyn KeyStore>,
        KeyCreationPolicy,
        Option<SoftwareKeyConsent>,
    ),
    String,
> {
    Ok((
        Box::new(MacOsKeyStore::new()),
        KeyCreationPolicy::PlatformProtectedOnly,
        None,
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn runtime_key_provider(
    _software_key_risk_acknowledged: bool,
) -> Result<
    (
        Box<dyn KeyStore>,
        KeyCreationPolicy,
        Option<SoftwareKeyConsent>,
    ),
    String,
> {
    Err("Signing-key storage is unsupported on this operating system.".into())
}

fn initialize_credential_store(app: &AppHandle) -> (Option<CredentialStore>, String) {
    let Some(protector) = credential_protector() else {
        return (
            None,
            "Protected credential storage is unsupported on this operating system.".into(),
        );
    };

    let data_dir = match app.path().app_data_dir() {
        Ok(path) => path,
        Err(_) => {
            return (
                None,
                "Could not resolve the application data directory.".into(),
            );
        }
    };

    if let Err(error) = fs::create_dir_all(&data_dir) {
        return (
            None,
            format!("Could not create the application data directory: {error}"),
        );
    }

    match CredentialStore::open(data_dir.join("credentials.sqlite3"), protector) {
        Ok(store) => (
            Some(store),
            "Protected credential storage is ready.".into(),
        ),
        Err(_) => (
            None,
            "Protected credential storage could not be opened. Check directory access and the OS credential service."
                .into(),
        ),
    }
}

impl DesktopVerificationProvider {
    fn resolve(&self, request_id: &str, approved: bool) -> Result<(), String> {
        let parsed_id = Uuid::parse_str(request_id)
            .map_err(|_| "Approval request is unknown or expired.".to_owned())?;
        if parsed_id.hyphenated().to_string() != request_id {
            return Err("Approval request is unknown or expired.".into());
        }

        if !approved {
            let mut approvals = self
                .pending
                .lock()
                .map_err(|_| "Approval state is unavailable.".to_owned())?;
            if approvals
                .get(request_id)
                .is_some_and(|approval| approval.responding)
            {
                return Err("Approval request is already being confirmed.".into());
            }
            let pending = approvals
                .remove(request_id)
                .ok_or_else(|| "Approval request is unknown or expired.".to_owned())?;
            let result = pending
                .sender
                .send(VerificationDecision::Rejected)
                .map_err(|_| "Approval request is no longer active.".to_owned());
            audit::record(
                audit::Event::UserApproval,
                if result.is_ok() {
                    audit::Outcome::Rejected
                } else {
                    audit::Outcome::Failure
                },
            );
            return result;
        }

        let (relying_party_id, relying_party_name, action) = {
            let mut pending = self
                .pending
                .lock()
                .map_err(|_| "Approval state is unavailable.".to_owned())?;
            let approval = pending
                .get_mut(request_id)
                .ok_or_else(|| "Approval request is unknown or expired.".to_owned())?;
            if approval.responding {
                return Err("Approval request is already being confirmed.".into());
            }
            approval.responding = true;
            (
                approval.relying_party_id.clone(),
                approval.relying_party_name.clone(),
                approval.action,
            )
        };
        let name = relying_party_name
            .as_deref()
            .map(|name| format!("{name} ({relying_party_id})"))
            .unwrap_or(relying_party_id);
        let message = format!(
            "{name} is requesting: {action}. Continue only if you initiated this action. Approving here authorizes this request to use the authenticator."
        );
        let decision = if confirm_native_action(
            &self.app,
            "Confirm authenticator request",
            &message,
        )
        .is_ok()
        {
            VerificationDecision::Approved
        } else {
            VerificationDecision::Rejected
        };
        let pending = self
            .pending
            .lock()
            .map_err(|_| "Approval state is unavailable.".to_owned())?
            .remove(request_id)
            .ok_or_else(|| "Approval request is unknown or expired.".to_owned())?;
        let outcome = if decision == VerificationDecision::Approved {
            audit::Outcome::Success
        } else {
            audit::Outcome::Rejected
        };
        let result = pending
            .sender
            .send(decision)
            .map_err(|_| "Approval request is no longer active.".to_owned());
        audit::record(
            audit::Event::UserApproval,
            if result.is_ok() {
                outcome
            } else {
                audit::Outcome::Failure
            },
        );
        result
    }
}

impl UserVerification for DesktopVerificationProvider {
    fn request_confirmation(
        &self,
        request: &VerificationRequest,
        timeout: Duration,
    ) -> Result<VerificationDecision, PlatformError> {
        let request_id = Uuid::new_v4().to_string();
        let prompt = ApprovalPrompt {
            request_id: request_id.clone(),
            relying_party_id: request.relying_party_id.clone(),
            relying_party_name: request.relying_party_name.clone(),
            action: match request.action {
                VerificationAction::RegisterCredential => "Register credential",
                VerificationAction::Authenticate => "Authenticate",
                VerificationAction::CredentialExclusionCheck => "Check existing credential",
                VerificationAction::ResetAuthenticator => "Reset authenticator",
            },
            timeout_millis: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
        };
        let (sender, receiver) = mpsc::sync_channel(1);
        self.pending
            .lock()
            .map_err(|_| {
                PlatformError::new(
                    PlatformErrorKind::UserVerificationUnavailable,
                    HostPlatform::current(),
                    "approval state is unavailable",
                )
            })?
            .insert(
                request_id.clone(),
                PendingApproval {
                    sender,
                    relying_party_id: request.relying_party_id.clone(),
                    relying_party_name: request.relying_party_name.clone(),
                    action: prompt.action,
                    responding: false,
                },
            );

        if self.app.emit("approval-request", prompt).is_err() {
            if let Ok(mut pending) = self.pending.lock() {
                pending.remove(&request_id);
            }
            return Err(PlatformError::new(
                PlatformErrorKind::UserVerificationUnavailable,
                HostPlatform::current(),
                "could not deliver the approval request to the desktop UI",
            ));
        }

        match receiver.recv_timeout(timeout) {
            Ok(decision) => Ok(decision),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if let Ok(mut pending) = self.pending.lock() {
                    pending.remove(&request_id);
                }
                Err(PlatformError::new(
                    PlatformErrorKind::Timeout,
                    HostPlatform::current(),
                    "approval request timed out",
                ))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(PlatformError::new(
                PlatformErrorKind::UserVerificationUnavailable,
                HostPlatform::current(),
                "approval response channel closed",
            )),
        }
    }

    fn cancel_pending(&self) {
        let pending = match self.pending.lock() {
            Ok(mut pending) => std::mem::take(&mut *pending),
            Err(_) => return,
        };
        for (request_id, approval) in pending {
            let _ = approval.sender.send(VerificationDecision::Cancelled);
            let _ = self.app.emit("approval-cancelled", request_id);
        }
    }
}

fn confirm_native_action(app: &AppHandle, title: &str, message: &str) -> Result<(), String> {
    let confirmed = app
        .dialog()
        .message(message)
        .title(title)
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancel)
        .blocking_show();
    if confirmed {
        Ok(())
    } else {
        Err("Action cancelled by the user.".into())
    }
}

#[tauri::command]
fn platform_status(state: tauri::State<'_, DesktopState>) -> PlatformStatus {
    let product = ProductInfo::current();
    let host_platform = match HostPlatform::current() {
        HostPlatform::Windows => "Windows",
        HostPlatform::MacOs => "macOS",
        HostPlatform::Linux => "Linux",
        HostPlatform::Other => "Unsupported operating system",
    };

    let runtime = state.virtual_hid.lock().ok();
    let virtual_hid_available = runtime
        .as_ref()
        .is_some_and(|status| status.virtual_hid_available);
    let device_attached = runtime
        .as_ref()
        .is_some_and(|status| status.device_attached);
    let authenticator_running = runtime
        .as_ref()
        .is_some_and(|status| status.authenticator_running);
    let runtime_message = runtime
        .as_ref()
        .map(|status| status.status_message.clone())
        .unwrap_or_else(|| "Virtual HID runtime state is unavailable.".into());
    let runtime_owns_store = state.runtime.lock().ok().is_some_and(|runtime| {
        runtime
            .as_ref()
            .is_some_and(|runtime| !runtime.worker.is_finished())
    });
    let credential_store_available = state.credential_store_available
        && (runtime_owns_store
            || state
                .credential_store
                .lock()
                .ok()
                .is_some_and(|store| store.is_some()));
    let key_storage_status = runtime
        .as_ref()
        .map(|status| status.key_storage_status.clone())
        .unwrap_or_default();
    let client_pin_status = if !state.credential_store_available {
        "Unavailable"
    } else {
        match state.credential_store.lock() {
            Ok(store) => match store.as_ref() {
                Some(store) if store.pin_state().verifier().is_some() => "Configured",
                Some(_) => "Not configured",
                None => "Unavailable",
            },
            Err(_) => "Unavailable",
        }
    };

    PlatformStatus {
        product_name: product.name,
        product_version: product.version,
        host_platform,
        virtual_hid_available,
        device_attached,
        key_storage_status,
        desktop_approval_status: "Available (desktop and native per-request confirmation)",
        client_pin_status,
        native_user_verification_status: "Not implemented",
        credential_store_available,
        credential_store_status: if credential_store_available {
            state.credential_store_status.clone()
        } else if state.credential_store_available {
            "Credential storage is unavailable after the authenticator service stopped.".into()
        } else {
            state.credential_store_status.clone()
        },
        status_message: if runtime_message.is_empty() {
            format!(
                "Virtual HID backend is ready on {host_platform}; browser WebAuthn compatibility is unverified."
            )
        } else {
            runtime_message
        },
        authenticator_running,
    }
}

#[tauri::command]
fn start_authenticator(
    app: AppHandle,
    state: tauri::State<'_, DesktopState>,
) -> Result<(), String> {
    let mut runtime = state
        .runtime
        .lock()
        .map_err(|_| "Runtime state is unavailable.")?;
    if let Some(existing) = runtime.take() {
        if !existing.worker.is_finished() {
            *runtime = Some(existing);
            return Err("The authenticator is already starting or running.".into());
        }
        if existing.worker.join().is_err() {
            audit::record(audit::Event::RuntimeFailure, audit::Outcome::Failure);
            return Err("The previous authenticator session failed.".into());
        }
    }
    if !credential_store_is_available(&state) {
        audit::record(audit::Event::RuntimeStartRequested, audit::Outcome::Failure);
        return Err(credential_store_status(&state));
    }
    let backend = ghost_platform::host_virtual_hid_backend();
    let availability = backend.availability();
    if availability.state != CapabilityState::Available {
        audit::record(audit::Event::RuntimeStartRequested, audit::Outcome::Failure);
        return Err(availability
            .detail
            .unwrap_or_else(|| "Virtual HID is unavailable.".into()));
    }
    let software_key_risk_acknowledged = if HostPlatform::current() == HostPlatform::Linux {
        confirm_native_action(
            &app,
            "Use Linux software signing keys?",
            "Signing keys will be created in software and stored through Linux Secret Service. Protection depends on that service's configuration, and users with access to the account or secret store may be able to extract keys. Accepting allows software-key creation for this authenticator runtime session only.",
        )?;
        true
    } else {
        false
    };
    let (key_store, key_creation_policy, software_key_consent) =
        runtime_key_provider(software_key_risk_acknowledged)?;

    let (stop_tx, stop_rx) = mpsc::sync_channel(1);
    let store = Arc::clone(&state.credential_store);
    let verification: Arc<dyn UserVerification> = state.verification.clone();
    let status = Arc::clone(&state.virtual_hid);
    let key_storage_status = match key_creation_policy {
        KeyCreationPolicy::PlatformProtectedOnly => "Platform-protected signing key",
        KeyCreationPolicy::SoftwareKeyAfterExplicitConsent => "Software key (session consent)",
    };
    let worker = std::thread::Builder::new()
        .name(format!("ghost-fido-{}-authenticator", std::env::consts::OS))
        .spawn(move || {
            authenticator_runtime::run(
                store,
                backend,
                verification,
                status,
                stop_rx,
                key_store,
                key_creation_policy,
                software_key_consent,
            );
        })
        .map_err(|error| {
            audit::record(audit::Event::RuntimeStartRequested, audit::Outcome::Failure);
            format!("Could not start authenticator runtime: {error}")
        })?;
    if let Ok(mut status) = state.virtual_hid.lock() {
        status.authenticator_running = true;
        status.key_storage_status = key_storage_status.into();
        status.status_message = "Starting virtual authenticator…".into();
    }
    *runtime = Some(RuntimeHandle {
        stop: stop_tx,
        worker,
    });
    audit::record(audit::Event::RuntimeStartRequested, audit::Outcome::Success);
    Ok(())
}

#[tauri::command]
fn stop_authenticator(state: tauri::State<'_, DesktopState>) -> Result<(), String> {
    stop_runtime(&state)
}

fn stop_runtime(state: &DesktopState) -> Result<(), String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "Runtime state is unavailable.")?
        .take();
    if let Some(runtime) = runtime {
        let _ = runtime.stop.send(());
        if runtime.worker.join().is_err() {
            audit::record(audit::Event::RuntimeFailure, audit::Outcome::Failure);
            return Err("Authenticator runtime stopped unexpectedly.".to_owned());
        }
    }
    Ok(())
}

fn with_stopped_credential_store<T>(
    state: &DesktopState,
    operation: impl FnOnce(&mut CredentialStore) -> Result<T, String>,
) -> Result<T, String> {
    let mut runtime = state
        .runtime
        .lock()
        .map_err(|_| "Runtime state is unavailable.")?;
    if runtime
        .as_ref()
        .is_some_and(|runtime| !runtime.worker.is_finished())
    {
        return Err("Stop the authenticator before managing credentials.".into());
    }
    if let Some(runtime) = runtime.take() {
        runtime
            .worker
            .join()
            .map_err(|_| "The authenticator stopped unexpectedly.".to_owned())?;
    }
    let mut store_slot = state
        .credential_store
        .lock()
        .map_err(|_| "Credential storage is unavailable.")?;
    let store = store_slot
        .as_mut()
        .ok_or_else(|| credential_store_status(state))?;
    operation(store)
}

fn credential_store_is_available(state: &DesktopState) -> bool {
    state.credential_store_available
        && state
            .credential_store
            .lock()
            .ok()
            .is_some_and(|store| store.is_some())
}

fn credential_store_status(state: &DesktopState) -> String {
    if state.credential_store_available {
        "Credential storage is unavailable after the authenticator service stopped.".into()
    } else {
        state.credential_store_status.clone()
    }
}

#[tauri::command]
fn set_client_pin(
    app: AppHandle,
    state: tauri::State<'_, DesktopState>,
    current_pin: Option<String>,
    new_pin: String,
) -> Result<(), String> {
    let current_pin = current_pin.map(Zeroizing::new);
    let new_pin = Zeroizing::new(new_pin);
    if new_pin.len() > PIN_MAX_UTF8_BYTES
        || current_pin
            .as_ref()
            .is_some_and(|pin| pin.len() > PIN_MAX_UTF8_BYTES)
    {
        audit::record(
            audit::Event::ClientPinConfiguration,
            audit::Outcome::Failure,
        );
        return Err(format!(
            "PIN values must not exceed {PIN_MAX_UTF8_BYTES} UTF-8 bytes."
        ));
    }

    let result = with_stopped_credential_store(&state, |store| {
        confirm_native_action(
            &app,
            "Change authenticator PIN",
            "Set or change the authenticator PIN? The verifier will be stored in this computer's protected credential store.",
        )?;
        configure_client_pin(
            store,
            current_pin.as_ref().map(|pin| pin.as_bytes()),
            new_pin.as_bytes(),
        )
        .map_err(|error| match error {
            PinManagementError::ProtectedStorageRequired => {
                "Protected credential storage is required to configure a PIN.".into()
            }
            PinManagementError::CurrentPinRequired => "Enter the current authenticator PIN.".into(),
            PinManagementError::PinNotSet => "No authenticator PIN is configured.".into(),
            PinManagementError::PinBlocked => {
                "The authenticator PIN is blocked. Reset the authenticator to configure a new PIN."
                    .into()
            }
            PinManagementError::InvalidPin => {
                "The new PIN does not meet the authenticator PIN policy.".into()
            }
            PinManagementError::InvalidCurrentPin => "The current PIN is incorrect.".into(),
            PinManagementError::Persistence => "The protected PIN state could not be saved.".into(),
        })
    });
    audit::record(
        audit::Event::ClientPinConfiguration,
        if result.is_ok() {
            audit::Outcome::Success
        } else {
            audit::Outcome::Failure
        },
    );
    result
}

#[tauri::command]
fn list_credentials(
    state: tauri::State<'_, DesktopState>,
) -> Result<Vec<CredentialSummary>, String> {
    with_stopped_credential_store(&state, |store| {
        Ok(store
            .managed_credentials()
            .into_iter()
            .map(|credential| CredentialSummary {
                creation_order: credential.creation_order,
                relying_party_id: credential.relying_party_id,
                user_name: credential.user_name,
                user_display_name: credential.user_display_name,
                key_protection: match credential.key_metadata.protection {
                    ghost_fido_core::CredentialKeyProtection::HardwareBacked => "Hardware-backed",
                    ghost_fido_core::CredentialKeyProtection::OsProtected => "OS-protected",
                    ghost_fido_core::CredentialKeyProtection::Software => "Software key",
                },
                exportable: credential.key_metadata.exportable,
                discoverable: credential.discoverable,
            })
            .collect())
    })
}

#[tauri::command]
fn delete_credential(
    app: AppHandle,
    state: tauri::State<'_, DesktopState>,
    creation_order: u64,
) -> Result<(), String> {
    let result = with_stopped_credential_store(&state, |store| {
        let credential = store
            .by_creation_order(creation_order)
            .ok_or_else(|| "The credential no longer exists.".to_owned())?;
        let relying_party = credential
            .relying_party_id
            .as_deref()
            .unwrap_or("unknown relying party");
        let user = credential
            .user_display_name
            .as_deref()
            .or(credential.user_name.as_deref())
            .unwrap_or("unknown user");
        confirm_native_action(
            &app,
            "Delete credential",
            &format!("Delete the credential for {user} at {relying_party}? This cannot be undone."),
        )?;
        let reference = String::from_utf8(credential.key_handle.as_bytes().to_vec())
            .map_err(|_| "The credential key reference is invalid.".to_owned())?;
        management_key_store()?
            .delete_key(&KeyReference::new(reference))
            .map_err(|error| {
                format!(
                    "The credential was kept because its signing key could not be deleted: {}",
                    error.detail
                )
            })?;
        store
            .remove_by_creation_order(creation_order)
            .map(|_| ())
            .map_err(|_| {
                "The signing key was deleted, but credential metadata could not be removed. Retry deletion to finish cleanup.".to_owned()
            })
    });
    audit::record(
        audit::Event::CredentialDeletion,
        if result.is_ok() {
            audit::Outcome::Success
        } else {
            audit::Outcome::Failure
        },
    );
    result
}

#[tauri::command]
fn reset_credentials(
    app: AppHandle,
    state: tauri::State<'_, DesktopState>,
) -> Result<usize, String> {
    let result = with_stopped_credential_store(&state, |store| {
        confirm_native_action(
            &app,
            "Reset authenticator",
            "Delete all credentials and signing keys from this computer? This cannot be undone.",
        )?;
        let references = store
            .provider_key_handles()
            .into_iter()
            .map(|handle| {
                String::from_utf8(handle.as_bytes().to_vec())
                    .map(KeyReference::new)
                    .map_err(|_| "A credential key reference is invalid.".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let key_store = management_key_store()?;
        for (index, reference) in references.iter().enumerate() {
            key_store.delete_key(reference).map_err(|error| {
                format!(
                    "Could not delete signing key {} of {}. Credential metadata was kept; resolve the provider error before retrying reset. {}",
                    index + 1,
                    references.len(),
                    error.detail
                )
            })?;
        }
        store.clear().map_err(|_| {
            "All signing keys were deleted, but credential metadata could not be cleared. Retry reset to finish cleanup.".to_owned()
        })
    });
    audit::record(
        audit::Event::AuthenticatorReset,
        if result.is_ok() {
            audit::Outcome::Success
        } else {
            audit::Outcome::Failure
        },
    );
    result
}

#[tauri::command]
fn respond_approval(
    state: tauri::State<'_, DesktopState>,
    request_id: String,
    approved: bool,
) -> Result<(), String> {
    state.verification.resolve(&request_id, approved)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            audit::init(app.path().app_log_dir().ok());
            let (store, status) = initialize_credential_store(app.handle());
            let store_available = store.is_some();
            audit::record(
                audit::Event::CredentialStoreInitialization,
                if store_available {
                    audit::Outcome::Success
                } else {
                    audit::Outcome::Failure
                },
            );
            let backend = ghost_platform::host_virtual_hid_backend();
            let availability = backend.availability();
            let platform_name = match HostPlatform::current() {
                HostPlatform::Windows => "Windows",
                HostPlatform::MacOs => "macOS",
                HostPlatform::Linux => "Linux",
                HostPlatform::Other => "this operating system",
            };
            let (virtual_hid_available, runtime_message) = (
                availability.state == CapabilityState::Available,
                availability.detail.unwrap_or_else(|| {
                    format!("Virtual FIDO HID is available on {platform_name}.")
                }),
            );
            let runtime_status = RuntimeStatus {
                virtual_hid_available,
                key_storage_status: (match HostPlatform::current() {
                    HostPlatform::Linux => "Signing key consent required",
                    HostPlatform::Windows => "Windows TPM-backed signing key required",
                    HostPlatform::MacOs => "Secure Enclave-backed signing key required",
                    HostPlatform::Other => "Protected signing-key provider unavailable",
                })
                .into(),
                status_message: runtime_message,
                ..RuntimeStatus::default()
            };
            app.manage(DesktopState {
                credential_store: Arc::new(Mutex::new(store)),
                credential_store_available: store_available,
                credential_store_status: status,
                verification: Arc::new(DesktopVerificationProvider {
                    app: app.handle().clone(),
                    pending: Mutex::new(HashMap::new()),
                }),
                virtual_hid: Arc::new(Mutex::new(runtime_status)),
                runtime: Mutex::new(None),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            platform_status,
            respond_approval,
            start_authenticator,
            stop_authenticator,
            list_credentials,
            delete_credential,
            reset_credentials,
            set_client_pin
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            if matches!(event, tauri::RunEvent::Exit) {
                if let Some(state) = app.try_state::<DesktopState>() {
                    let _ = stop_runtime(&state);
                }
            }
        })
}

mod audit;
mod authenticator_runtime;
