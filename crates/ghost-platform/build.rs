use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    println!("cargo:rerun-if-env-changed=GHOST_FIDO_LINUX_VENDOR_ID");
    println!("cargo:rerun-if-env-changed=GHOST_FIDO_LINUX_PRODUCT_ID");
    println!("cargo:rerun-if-env-changed=GHOST_FIDO_MACOS_VENDOR_ID");
    println!("cargo:rerun-if-env-changed=GHOST_FIDO_MACOS_PRODUCT_ID");
    println!("cargo:rerun-if-changed=../../platforms/macos/corehid/Package.swift");
    println!("cargo:rerun-if-changed=../../platforms/macos/corehid/GhostFidoVirtualDevice.swift");
    println!("cargo:rerun-if-changed=../../platforms/macos/corehid/GhostFidoCoreHIDBridge.swift");

    let target = env::var("TARGET").unwrap_or_default();
    if target.ends_with("-linux-gnu") || target.ends_with("-linux-musl") {
        configure_product_identity("LINUX");
        return;
    }
    if !target.ends_with("-apple-darwin") {
        return;
    }

    configure_product_identity("MACOS");
    build_corehid_bridge();
}

fn configure_product_identity(platform: &str) {
    let vendor_name = format!("GHOST_FIDO_{platform}_VENDOR_ID");
    let product_name = format!("GHOST_FIDO_{platform}_PRODUCT_ID");
    let vendor_id = parse_product_id(&vendor_name);
    let product_id = parse_product_id(&product_name);

    match (vendor_id, product_id) {
        (Some(vendor_id), Some(product_id)) => {
            println!("cargo:rustc-env={vendor_name}={vendor_id}");
            println!("cargo:rustc-env={product_name}={product_id}");
        }
        (None, None) => println!(
            "cargo:warning={platform} virtual HID identity is missing or invalid; the backend will remain unavailable"
        ),
        _ => println!(
            "cargo:warning=both valid {vendor_name} and {product_name} values are required; the {platform} backend will remain unavailable"
        ),
    }
}

fn parse_product_id(name: &str) -> Option<u16> {
    let value = env::var(name).ok()?;
    let value = value.trim();
    let parsed = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(|| value.parse::<u32>(), |hex| u32::from_str_radix(hex, 16))
        .ok()?;
    (1..0xFFFF).contains(&parsed).then_some(parsed as u16)
}

fn build_corehid_bridge() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let package_dir = manifest_dir.join("../../platforms/macos/corehid");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("output dir"));
    let scratch_dir = out_dir.join("swift-package");
    let target = env::var("TARGET").expect("target triple");
    let swift_triple = match target.as_str() {
        "x86_64-apple-darwin" => "x86_64-apple-macosx15.0",
        "aarch64-apple-darwin" => "arm64-apple-macosx15.0",
        _ => panic!("unsupported macOS target for CoreHID bridge: {target}"),
    };

    let mut build = Command::new("swift");
    build
        .arg("build")
        .arg("--package-path")
        .arg(&package_dir)
        .arg("--scratch-path")
        .arg(&scratch_dir)
        .arg("--triple")
        .arg(swift_triple)
        .arg("--configuration")
        .arg("release")
        .arg("--product")
        .arg("ghost_fido_corehid");
    run(&mut build, "Swift CoreHID static library build");

    let bin_dir = swift_bin_dir(&package_dir, &scratch_dir, swift_triple);
    let library = bin_dir.join("libghost_fido_corehid.a");
    if !library.is_file() {
        panic!("Swift package did not produce {}", library.display());
    }

    println!("cargo:rustc-link-search=native={}", bin_dir.display());
    println!("cargo:rustc-link-lib=static=ghost_fido_corehid");
    println!("cargo:rustc-link-lib=framework=CoreHID");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=CryptoKit");
    println!(
        "cargo:rerun-if-changed={}",
        package_dir.join("Package.swift").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        package_dir.join("GhostFidoVirtualDevice.swift").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        package_dir.join("GhostFidoCoreHIDBridge.swift").display()
    );
}

fn swift_bin_dir(package_dir: &Path, scratch_dir: &Path, triple: &str) -> PathBuf {
    let output = Command::new("swift")
        .arg("build")
        .arg("--show-bin-path")
        .arg("--package-path")
        .arg(package_dir)
        .arg("--scratch-path")
        .arg(scratch_dir)
        .arg("--triple")
        .arg(triple)
        .arg("--configuration")
        .arg("release")
        .output()
        .expect("run swift build --show-bin-path");
    if !output.status.success() {
        panic!(
            "Swift did not report its build output path: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    PathBuf::from(String::from_utf8_lossy(&output.stdout).trim())
}

fn run(command: &mut Command, description: &str) {
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("could not start {description}: {error}"));
    if !status.success() {
        panic!("{description} failed with status {status}");
    }
}
