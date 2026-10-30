// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "GhostFidoCoreHID",
    platforms: [.macOS(.v15)],
    products: [
        .library(
            name: "ghost_fido_corehid",
            type: .static,
            targets: ["GhostFidoCoreHID"]
        ),
    ],
    targets: [
        .target(
            name: "GhostFidoCoreHID",
            path: ".",
            sources: ["GhostFidoVirtualDevice.swift", "GhostFidoCoreHIDBridge.swift"],
            linkerSettings: [
                .linkedFramework("CoreHID"),
                .linkedFramework("AppKit"),
                .linkedFramework("Foundation"),
                .linkedFramework("Security"),
            ]
        ),
    ]
)
