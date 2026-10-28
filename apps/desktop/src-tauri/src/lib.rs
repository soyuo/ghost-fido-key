use ghost_fido_core::{CredentialProtector, CredentialStore, ProductInfo};
use ghost_platform::{
    CapabilityState, DeviceState, HostPlatform, UnavailableBackend, VirtualHidBackend,
};
use serde::Serialize;
use std::{
    fs,
    sync::{Arc, Mutex},
};
use tauri::{AppHandle, Manager};

struct DesktopState {
    credential_store: Mutex<Option<CredentialStore>>,
    credential_store_status: String,
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
    let backend = UnavailableBackend;
    let capabilities = backend.capabilities();
    let host_platform = match HostPlatform::current() {
        HostPlatform::Windows => "Windows",
        HostPlatform::MacOs => "macOS",
        HostPlatform::Linux => "Linux",
        HostPlatform::Other => "Unsupported operating system",
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
        virtual_hid_available: capabilities.virtual_hid.state == CapabilityState::Available,
        device_attached: backend.state() == DeviceState::Attached,
        key_storage_status: capability_label(capabilities.protected_key_storage.state),
        user_verification_status: capability_label(capabilities.user_verification.state),
        credential_store_available,
        credential_store_status,
        status_message: capabilities
            .virtual_hid
            .detail
            .unwrap_or_else(|| format!("Virtual FIDO HID is unavailable on {host_platform}.")),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let (store, status) = initialize_credential_store(app.handle());
            app.manage(DesktopState {
                credential_store: Mutex::new(store),
                credential_store_status: status,
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![platform_status])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
