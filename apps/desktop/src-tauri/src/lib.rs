use ghost_fido_core::ProductInfo;
use ghost_platform::{DeviceState, HostPlatform, UnavailableBackend, VirtualHidBackend};
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PlatformStatus {
    product_name: &'static str,
    product_version: &'static str,
    host_platform: &'static str,
    virtual_hid_available: bool,
    device_attached: bool,
    status_message: String,
}

#[tauri::command]
fn platform_status() -> PlatformStatus {
    let product = ProductInfo::current();
    let backend = UnavailableBackend;
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
        virtual_hid_available: backend.is_available(),
        device_attached: backend.state() == DeviceState::Attached,
        status_message: format!("Virtual FIDO HID is not implemented for {host_platform} yet."),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![platform_status])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
