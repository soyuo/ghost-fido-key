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

enum GhostFidoCoreHIDError: Error, Equatable {
    case invalidIdentity
    case alreadyActive
    case notActive
    case invalidReportSize
    case timedOut
}

@available(macOS 15.0, *)
private final class GhostFidoOutputReportQueue: @unchecked Sendable {
    private let condition = NSCondition()
    private let capacity = 16
    private var reports: [Data] = []
    private var active = false

    func activate() {
        condition.lock()
        active = true
        condition.broadcast()
        condition.unlock()
    }

    func deactivate() {
        condition.lock()
        active = false
        reports.removeAll(keepingCapacity: false)
        condition.broadcast()
        condition.unlock()
    }

    func enqueue(_ report: Data) throws {
        guard report.count == 64 else {
            throw HIDDeviceError.badArgument
        }

        condition.lock()
        defer { condition.unlock() }
        guard active else {
            throw HIDDeviceError.notReady
        }
        guard reports.count < capacity else {
            throw HIDDeviceError.noResources
        }
        reports.append(report)
        condition.signal()
    }

    func dequeue(timeoutMilliseconds: UInt64) throws -> Data {
        let deadline = Date().addingTimeInterval(Double(timeoutMilliseconds) / 1_000)
        condition.lock()
        defer { condition.unlock() }

        while reports.isEmpty && active {
            if !condition.wait(until: deadline), reports.isEmpty {
                throw GhostFidoCoreHIDError.timedOut
            }
        }
        guard active else {
            throw GhostFidoCoreHIDError.notActive
        }
        return reports.removeFirst()
    }
}

@available(macOS 15.0, *)
private final class GhostFidoVirtualDeviceDelegate: HIDVirtualDeviceDelegate, Sendable {
    private let outputReports: GhostFidoOutputReportQueue

    init(outputReports: GhostFidoOutputReportQueue) {
        self.outputReports = outputReports
    }

    func hidVirtualDevice(
        _ device: HIDVirtualDevice,
        receivedSetReportRequestOfType type: HIDReportType,
        id: HIDReportID?,
        data: Data
    ) async throws {
        guard type == .output, id == nil else {
            throw HIDDeviceError.unsupported
        }
        try outputReports.enqueue(data)
    }

    func hidVirtualDevice(
        _ device: HIDVirtualDevice,
        receivedGetReportRequestOfType type: HIDReportType,
        id: HIDReportID?,
        maxSize: Int
    ) async throws -> Data {
        guard type == .input, id == nil else {
            throw HIDDeviceError.unsupported
        }
        guard maxSize >= 64 else {
            throw HIDDeviceError.messageTooLarge
        }
        // The CTAPHID descriptor has no report IDs and no feature reports.
        return Data(repeating: 0, count: 64)
    }
}

/// CoreHID lifecycle and bounded report channel for the Rust/macOS boundary.
///
/// Availability is macOS 15.0 or later and additionally depends on the signed
/// app carrying Apple's virtual HID entitlement. The app supplies only product
/// IDs assigned to this product; this type does not invent identity values.
@available(macOS 15.0, *)
actor GhostFidoVirtualDevice {
    private var device: HIDVirtualDevice?
    private var delegate: GhostFidoVirtualDeviceDelegate?
    private let outputReports = GhostFidoOutputReportQueue()

    func activate(vendorID: UInt32, productID: UInt32) async throws {
        guard device == nil else {
            throw GhostFidoCoreHIDError.alreadyActive
        }
        guard (1..<0xFFFF).contains(vendorID), (1..<0xFFFF).contains(productID) else {
            throw GhostFidoCoreHIDError.invalidIdentity
        }

        let properties = HIDVirtualDevice.Properties(
            descriptor: Data(ghostFidoReportDescriptor),
            vendorID: vendorID,
            productID: productID,
            transport: .virtual,
            product: "Ghost FIDO Key",
            manufacturer: "Ghost FIDO Key"
        )
        guard let newDevice = HIDVirtualDevice(properties: properties) else {
            throw HIDDeviceError.noResources
        }

        let newDelegate = GhostFidoVirtualDeviceDelegate(outputReports: outputReports)
        await newDevice.activate(delegate: newDelegate)
        guard newDevice.hidDevice != nil else {
            throw HIDDeviceError.notReady
        }
        device = newDevice
        delegate = newDelegate
        outputReports.activate()
    }

    func dispatchInputReport(_ report: Data) async throws {
        guard report.count == 64 else {
            throw GhostFidoCoreHIDError.invalidReportSize
        }
        guard let device else {
            throw GhostFidoCoreHIDError.notActive
        }
        try await device.dispatchInputReport(data: report, timestamp: SuspendingClock.now)
    }

    func receiveOutputReport(timeoutMilliseconds: UInt64) async throws -> Data {
        let outputReports = outputReports
        return try await Task.detached {
            try outputReports.dequeue(timeoutMilliseconds: timeoutMilliseconds)
        }.value
    }

    func deactivate() {
        outputReports.deactivate()
        delegate = nil
        // Releasing the CoreHID actor ends the virtual-device lifetime.
        device = nil
    }
}
