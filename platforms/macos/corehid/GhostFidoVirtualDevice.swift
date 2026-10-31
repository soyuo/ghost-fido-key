import CoreHID
import Dispatch
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
    private let lock = NSLock()
    private let capacity = 16
    private var reports: [Data] = []
    private var waiters: [DispatchSemaphore] = []
    private var active = false

    func activate() {
        lock.lock()
        active = true
        lock.unlock()
    }

    func deactivate() {
        lock.lock()
        active = false
        reports.removeAll(keepingCapacity: false)
        let blockedWaiters = waiters
        waiters.removeAll(keepingCapacity: false)
        lock.unlock()

        for waiter in blockedWaiters {
            waiter.signal()
        }
    }

    func enqueue(_ report: Data) throws {
        guard report.count == 64 else {
            throw HIDDeviceError.badArgument
        }

        lock.lock()
        guard active else {
            lock.unlock()
            throw HIDDeviceError.notReady
        }
        guard reports.count < capacity else {
            lock.unlock()
            throw HIDDeviceError.noResources
        }
        reports.append(report)
        let waiter = waiters.isEmpty ? nil : waiters.removeFirst()
        lock.unlock()
        waiter?.signal()
    }

    func dequeue(timeoutMilliseconds: UInt64) throws -> Data {
        let deadline = DispatchTime.now() + .milliseconds(Int(clamping: timeoutMilliseconds))

        while true {
            lock.lock()
            guard active else {
                lock.unlock()
                throw GhostFidoCoreHIDError.notActive
            }
            if !reports.isEmpty {
                let report = reports.removeFirst()
                lock.unlock()
                return report
            }

            let waiter = DispatchSemaphore(value: 0)
            waiters.append(waiter)
            lock.unlock()

            let signaled = waiter.wait(timeout: deadline) == .success

            lock.lock()
            waiters.removeAll { $0 === waiter }
            guard active else {
                lock.unlock()
                throw GhostFidoCoreHIDError.notActive
            }
            if !reports.isEmpty {
                let report = reports.removeFirst()
                lock.unlock()
                return report
            }
            lock.unlock()

            if !signaled {
                throw GhostFidoCoreHIDError.timedOut
            }
        }
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
