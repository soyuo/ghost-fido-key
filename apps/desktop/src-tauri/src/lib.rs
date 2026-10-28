use ghost_fido_core::ProductInfo;
use ghost_platform::{
    CapabilityState, DeviceState, HostPlatform, UnavailableBackend, VirtualHidBackend,
};
use serde::Serialize;

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
    status_message: String,
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
fn platform_status() -> PlatformStatus {
    let product = ProductInfo::current();
    let backend = UnavailableBackend;
    let capabilities = backend.capabilities();
    let host_platform = match HostPlatform::current() {
        HostPlatform::Windows => "Windows",
        HostPlatform::MacOs => "macOS",
        HostPlatform::Linux => "Linux",
        HostPlatform::Other => "Unsupported operating system",
    };

    PlatformStatus {
        product_name: product.name,
        product_version: product.version,
        host_platform,
        virtual_hid_available: capabilities.virtual_hid.state == CapabilityState::Available,
        device_attached: backend.state() == DeviceState::Attached,
        key_storage_status: capability_label(capabilities.protected_key_storage.state),
        user_verification_status: capability_label(capabilities.user_verification.state),
        status_message: capabilities
            .virtual_hid
            .detail
            .unwrap_or_else(|| format!("Virtual FIDO HID is unavailable on {host_platform}.")),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![platform_status])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
