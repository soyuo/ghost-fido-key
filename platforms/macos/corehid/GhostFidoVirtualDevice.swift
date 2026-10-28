import CoreHID
import Foundation

/// FIDO Alliance CTAPHID usage page 0xF1D0, usage 0x01, 64-byte reports.
let ghostFidoReportDescriptor: [UInt8] = [
    0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01,
    0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00,
    0x75, 0x08, 0x95, 0x40, 0x81, 0x02,
    0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00,
    0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xC0,
]

enum GhostFidoCoreHIDError: Error {
    case entitlementUnavailable
    case notImplemented
}

/// Native lifecycle boundary for the Rust/macOS bridge.
///
/// The bridge is deliberately incomplete until Apple grants the entitlement
/// and the distribution-signed path is validated.
actor GhostFidoVirtualDevice {
    private var device: HIDVirtualDevice?

    func activate() throws {
        // TODO: construct HIDVirtualDevice.Properties with the descriptor,
        // vendor/product metadata, and activate(delegate:). Do not use a
        // third-party VID/PID or report readiness before entitlement checks.
        throw GhostFidoCoreHIDError.notImplemented
    }

    func dispatchInputReport(_ report: Data) throws {
        guard report.count == 64 else {
            throw GhostFidoCoreHIDError.notImplemented
        }
        guard device != nil else {
            throw GhostFidoCoreHIDError.notImplemented
        }
        // TODO: await device.dispatchInputReport(data: report, timestamp: ...).
        throw GhostFidoCoreHIDError.notImplemented
    }

    func deactivate() {
        // TODO: release the active HIDVirtualDevice after the host is detached.
        device = nil
    }
}
