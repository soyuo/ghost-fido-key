use ghost_fido_core::ProductInfo;
use ghost_platform::{HostPlatform, UnavailableBackend, VirtualHidBackend};

fn main() {
    let product = ProductInfo::current();
    let backend = UnavailableBackend;

    println!("{} {}", product.name, product.version);
    println!("Host platform: {:?}", HostPlatform::current());
    println!("Virtual HID available: {}", backend.is_available());
    println!(
        "Scaffold only: CTAP workflows are not connected to live HID transport; UI and native platform integration remain incomplete."
    );
}
