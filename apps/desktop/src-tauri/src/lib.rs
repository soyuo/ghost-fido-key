use ghost_fido_core::{CredentialProtector, CredentialStore, ProductInfo};
use ghost_platform::{
    CapabilityState, CapabilityStatus, DeviceState, HostPlatform, PlatformError, PlatformErrorKind,
    UserVerification, VerificationAction, VerificationDecision, VerificationRequest,
    VirtualHidBackend,
};
use serde::Serialize;
use std::collections::HashMap;
use std::{
    fs,
    sync::{Arc, Mutex, mpsc, mpsc::SyncSender},
    time::Duration,
};
use tauri::{AppHandle, Emitter, Manager};
use uuid::Uuid;

struct DesktopState {
    credential_store: Mutex<Option<CredentialStore>>,
    credential_store_status: String,
    verification: DesktopVerificationProvider,
    virtual_hid: Mutex<Box<dyn VirtualHidBackend>>,
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
    key_storage_status: &'static str,
    user_verification_status: &'static str,
    credential_store_available: bool,
    credential_store_status: String,
    status_message: String,
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

    let (virtual_hid, device_attached) = match state.virtual_hid.lock() {
        Ok(backend) => (
            backend.availability(),
            backend.state() == DeviceState::Attached,
        ),
        Err(_) => (
            CapabilityStatus::unavailable(
                CapabilityState::Error,
                "Virtual HID adapter state is unavailable.",
            ),
            false,
        ),
    };

    let (credential_store_available, credential_store_status) = match state.credential_store.lock()
    {
        Ok(store) => (store.is_some(), state.credential_store_status.clone()),
        Err(_) => (false, "Credential storage state is unavailable.".into()),
    };

    PlatformStatus {
        product_name: product.name,
        product_version: product.version,
        host_platform,
        virtual_hid_available: virtual_hid.state == CapabilityState::Available,
        device_attached,
        key_storage_status: capability_label(CapabilityState::NotImplemented),
        user_verification_status: capability_label(CapabilityState::NotImplemented),
        credential_store_available,
        credential_store_status,
        status_message: virtual_hid
            .detail
            .unwrap_or_else(|| format!("Virtual FIDO HID is available on {host_platform}.")),
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
            app.manage(DesktopState {
                credential_store: Mutex::new(store),
                credential_store_status: status,
                verification: DesktopVerificationProvider {
                    app: app.handle().clone(),
                    pending: Mutex::new(HashMap::new()),
                },
                virtual_hid: Mutex::new(ghost_platform::host_virtual_hid_backend()),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![platform_status, respond_approval])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
