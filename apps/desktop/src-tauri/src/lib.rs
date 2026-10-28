use ghost_fido_core::{CredentialProtector, CredentialStore, ProductInfo};
use ghost_platform::{
    CapabilityState, HostPlatform, PlatformError, PlatformErrorKind, UserVerification,
    VerificationAction, VerificationDecision, VerificationRequest,
};
#[cfg(target_os = "linux")]
use ghost_platform::{KeyReference, KeyStore, LinuxKeyStore};
use serde::Serialize;
use std::collections::HashMap;
use std::{
    fs,
    sync::{Arc, Mutex, mpsc, mpsc::SyncSender},
    thread::JoinHandle,
    time::Duration,
};
use tauri::{AppHandle, Emitter, Manager};
use uuid::Uuid;

struct DesktopState {
    #[cfg(target_os = "linux")]
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
    pending: Mutex<HashMap<String, SyncSender<VerificationDecision>>>,
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
    user_verification_status: &'static str,
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
        let sender = self
            .pending
            .lock()
            .map_err(|_| "Approval state is unavailable.".to_owned())?
            .remove(request_id)
            .ok_or_else(|| "Approval request is unknown or expired.".to_owned())?;
        sender
            .send(if approved {
                VerificationDecision::Approved
            } else {
                VerificationDecision::Rejected
            })
            .map_err(|_| "Approval request is no longer active.".to_owned())
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
            .insert(request_id.clone(), sender);

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
        for (request_id, sender) in pending {
            let _ = sender.send(VerificationDecision::Cancelled);
            let _ = self.app.emit("approval-cancelled", request_id);
        }
    }
}

fn capability_label(state: CapabilityState) -> &'static str {
    match state {
        CapabilityState::Available => "사용 가능",
        CapabilityState::PermissionRequired => "권한 필요",
        CapabilityState::DriverMissing => "드라이버 없음",
        CapabilityState::EntitlementUnavailable => "entitlement 없음",
        CapabilityState::Unsupported => "지원하지 않음",
        CapabilityState::NotImplemented => "미구현",
        CapabilityState::Error => "오류",
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
    let key_storage_status = runtime
        .as_ref()
        .map(|status| status.key_storage_status.clone())
        .unwrap_or_default();

    PlatformStatus {
        product_name: product.name,
        product_version: product.version,
        host_platform,
        virtual_hid_available,
        device_attached,
        key_storage_status,
        user_verification_status: capability_label(CapabilityState::NotImplemented),
        credential_store_available: state.credential_store_available,
        credential_store_status: state.credential_store_status.clone(),
        status_message: if runtime_message.is_empty() {
            format!("Virtual FIDO HID is available on {host_platform}.")
        } else {
            runtime_message
        },
        authenticator_running,
    }
}

#[tauri::command]
fn start_authenticator(
    state: tauri::State<'_, DesktopState>,
    software_key_risk_acknowledged: bool,
) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        if !software_key_risk_acknowledged {
            return Err("Explicit acceptance of the software-key warning is required.".into());
        }
        let mut runtime = state
            .runtime
            .lock()
            .map_err(|_| "Runtime state is unavailable.")?;
        if let Some(existing) = runtime.take() {
            if !existing.worker.is_finished() {
                *runtime = Some(existing);
                return Err("The authenticator is already starting or running.".into());
            }
            existing
                .worker
                .join()
                .map_err(|_| "The previous authenticator session failed.")?;
        }
        if !state.credential_store_available {
            return Err(state.credential_store_status.clone());
        }
        let mut backend = ghost_platform::host_virtual_hid_backend();
        let availability = backend.availability();
        if availability.state != CapabilityState::Available {
            return Err(availability
                .detail
                .unwrap_or_else(|| "Virtual HID is unavailable.".into()));
        }
        let consent = ghost_platform::SoftwareKeyConsent::confirm_user_acceptance(true)
            .ok_or("Software-key consent was not recorded.")?;
        let (stop_tx, stop_rx) = mpsc::sync_channel(1);
        let store = Arc::clone(&state.credential_store);
        let verification: Arc<dyn UserVerification> = state.verification.clone();
        let status = Arc::clone(&state.virtual_hid);
        let worker = std::thread::Builder::new()
            .name("ghost-fido-linux-uhid".into())
            .spawn(move || {
                linux_runtime::run(store, backend, verification, status, stop_rx, consent);
            })
            .map_err(|error| format!("Could not start authenticator runtime: {error}"))?;
        if let Ok(mut status) = state.virtual_hid.lock() {
            status.authenticator_running = true;
            status.key_storage_status = "Software key (session consent)".into();
            status.status_message = "Starting virtual authenticator…".into();
        }
        *runtime = Some(RuntimeHandle {
            stop: stop_tx,
            worker,
        });
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = software_key_risk_acknowledged;
        let _ = state;
        Err("The authenticator runtime is currently implemented on Linux only.".into())
    }
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
        runtime
            .worker
            .join()
            .map_err(|_| "Authenticator runtime stopped unexpectedly.".to_owned())?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
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
        .ok_or_else(|| state.credential_store_status.clone())?;
    operation(store)
}

#[tauri::command]
fn list_credentials(
    state: tauri::State<'_, DesktopState>,
) -> Result<Vec<CredentialSummary>, String> {
    #[cfg(target_os = "linux")]
    {
        return with_stopped_credential_store(&state, |store| {
            Ok(store
                .managed_credentials()
                .into_iter()
                .map(|credential| CredentialSummary {
                    creation_order: credential.creation_order,
                    relying_party_id: credential.relying_party_id,
                    user_name: credential.user_name,
                    user_display_name: credential.user_display_name,
                    key_protection: match credential.key_metadata.protection {
                        ghost_fido_core::CredentialKeyProtection::HardwareBacked => {
                            "Hardware-backed"
                        }
                        ghost_fido_core::CredentialKeyProtection::OsProtected => "OS-protected",
                        ghost_fido_core::CredentialKeyProtection::Software => "Software key",
                    },
                    exportable: credential.key_metadata.exportable,
                    discoverable: credential.discoverable,
                })
                .collect())
        });
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = state;
        Err("Credential management is currently implemented on Linux only.".into())
    }
}

#[tauri::command]
fn delete_credential(
    state: tauri::State<'_, DesktopState>,
    creation_order: u64,
    confirmed: bool,
) -> Result<(), String> {
    if !confirmed {
        return Err("Explicit confirmation is required to delete a credential.".into());
    }
    #[cfg(target_os = "linux")]
    {
        return with_stopped_credential_store(&state, |store| {
            let credential = store
                .by_creation_order(creation_order)
                .ok_or_else(|| "The credential no longer exists.".to_owned())?;
            let reference = String::from_utf8(credential.key_handle.as_bytes().to_vec())
                .map_err(|_| "The credential key reference is invalid.".to_owned())?;
            LinuxKeyStore::new()
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
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state, creation_order);
        Err("Credential management is currently implemented on Linux only.".into())
    }
}

#[tauri::command]
fn reset_credentials(
    state: tauri::State<'_, DesktopState>,
    confirmed: bool,
) -> Result<usize, String> {
    if !confirmed {
        return Err("Explicit confirmation is required to reset credentials.".into());
    }
    #[cfg(target_os = "linux")]
    {
        return with_stopped_credential_store(&state, |store| {
            let references = store
                .provider_key_handles()
                .into_iter()
                .map(|handle| {
                    String::from_utf8(handle.as_bytes().to_vec())
                        .map(KeyReference::new)
                        .map_err(|_| "A credential key reference is invalid.".to_owned())
                })
                .collect::<Result<Vec<_>, _>>()?;
            let key_store = LinuxKeyStore::new();
            for (index, reference) in references.iter().enumerate() {
                key_store.delete_key(reference).map_err(|error| {
                    format!(
                        "Could not delete signing key {} of {}. Credential metadata was kept; retry reset after fixing the Secret Service issue. {}",
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
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = state;
        Err("Credential reset is currently implemented on Linux only.".into())
    }
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
        .setup(|app| {
            let (store, status) = initialize_credential_store(app.handle());
            let store_available = store.is_some();
            #[cfg(not(target_os = "linux"))]
            drop(store);
            let backend = ghost_platform::host_virtual_hid_backend();
            #[cfg(target_os = "linux")]
            let availability = backend.availability();
            #[cfg(not(target_os = "linux"))]
            drop(backend);
            #[cfg(target_os = "linux")]
            let (virtual_hid_available, runtime_message) = (
                availability.state == CapabilityState::Available,
                availability
                    .detail
                    .unwrap_or_else(|| "Virtual FIDO HID is available on Linux.".into()),
            );
            #[cfg(not(target_os = "linux"))]
            let (virtual_hid_available, runtime_message) = (
                false,
                "The authenticator runtime is not implemented for this operating system.".into(),
            );
            let runtime_status = RuntimeStatus {
                virtual_hid_available,
                key_storage_status: if cfg!(target_os = "linux") {
                    "Signing key consent required".into()
                } else {
                    "OS protected storage".into()
                },
                status_message: runtime_message,
                ..RuntimeStatus::default()
            };
            app.manage(DesktopState {
                #[cfg(target_os = "linux")]
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
            reset_credentials
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

#[cfg(target_os = "linux")]
mod linux_runtime;
