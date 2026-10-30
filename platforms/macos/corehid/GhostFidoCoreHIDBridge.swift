import CoreHID
import Foundation
import AppKit
import Security

private let ghostFidoVirtualHIDEntitlement = "com.apple.developer.hid.virtual.device"

/// Tracks user-session transitions only; this is not a screen-lock detector.
private final class GhostFidoSessionGeneration: @unchecked Sendable {
    static let shared = GhostFidoSessionGeneration()

    private let lock = NSLock()
    private var value: UInt64 = 0
    private var observers: [NSObjectProtocol] = []

    private init() {
        let center = NSWorkspace.shared.notificationCenter
        observers.append(center.addObserver(
            forName: NSWorkspace.sessionDidResignActiveNotification,
            object: nil,
            queue: nil
        ) { [weak self] _ in
            self?.advance()
        })
    }

    var current: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    private func advance() {
        lock.lock()
        value &+= 1
        lock.unlock()
    }
}

private enum GhostFidoCoreHIDBridgeStatus: Int32 {
    case success = 0
    case invalidArgument = 1
    case notPermitted = 2
    case timedOut = 3
    case notReady = 4
    case noResources = 5
    case ioError = 6
}

private final class GhostFidoCoreHIDResult<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Result<Value, Error>?

    func resolve(_ result: Result<Value, Error>) {
        lock.lock()
        self.result = result
        lock.unlock()
    }

    func take() -> Result<Value, Error> {
        lock.lock()
        defer { lock.unlock() }
        return result ?? .failure(HIDDeviceError.deviceError)
    }
}

private func waitForCoreHID<Value: Sendable>(
    _ operation: @escaping @Sendable () async throws -> Value
) throws -> Value {
    let semaphore = DispatchSemaphore(value: 0)
    let result = GhostFidoCoreHIDResult<Value>()
    Task.detached(priority: .userInitiated) {
        defer { semaphore.signal() }
        do {
            result.resolve(.success(try await operation()))
        } catch {
            result.resolve(.failure(error))
        }
    }
    semaphore.wait()
    return try result.take().get()
}

@available(macOS 15.0, *)
private final class GhostFidoCoreHIDHandle: Sendable {
    let device = GhostFidoVirtualDevice()
}

private func bridgeStatus(for error: Error) -> GhostFidoCoreHIDBridgeStatus {
    if let error = error as? HIDDeviceError {
        switch error {
        case .badArgument, .messageTooLarge:
            return .invalidArgument
        case .notPermitted, .notPrivileged:
            return .notPermitted
        case .timeout, .aborted:
            return .timedOut
        case .notReady:
            return .notReady
        case .noResources:
            return .noResources
        default:
            return .ioError
        }
    }

    if error as? GhostFidoCoreHIDError == .timedOut {
        return .timedOut
    }
    if error as? GhostFidoCoreHIDError == .invalidReportSize {
        return .invalidArgument
    }
    if error as? GhostFidoCoreHIDError == .notActive {
        return .notReady
    }
    return .ioError
}

private func processHasVirtualHIDEntitlement() -> Bool {
    var processCode: SecCode?
    guard SecCodeCopySelf(SecCSFlags(rawValue: 0), &processCode) == errSecSuccess,
          let processCode else {
        return false
    }

    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(processCode, SecCSFlags(rawValue: 0), &staticCode) == errSecSuccess,
          let staticCode else {
        return false
    }

    var information: CFDictionary?
    guard SecCodeCopySigningInformation(
        staticCode,
        SecCSFlags(rawValue: kSecCSSigningInformation),
        &information
    ) == errSecSuccess,
          let information else {
        return false
    }

    let signingInformation = information as NSDictionary
    let entitlements = signingInformation[kSecCodeInfoEntitlementsDict as String] as? NSDictionary
    return entitlements?[ghostFidoVirtualHIDEntitlement] as? Bool == true
}

/// Returns the generation advanced whenever macOS reports session switch-out.
@_cdecl("ghost_fido_corehid_session_generation")
public func ghostFidoCoreHIDSessionGeneration() -> UInt64 {
    GhostFidoSessionGeneration.shared.current
}

/// Reports readiness only when the process signature includes Apple's virtual HID entitlement.
@_cdecl("ghost_fido_corehid_check_readiness")
public func ghostFidoCoreHIDCheckReadiness(_ vendorID: UInt32, _ productID: UInt32) -> Int32 {
    guard (1..<0xFFFF).contains(vendorID), (1..<0xFFFF).contains(productID) else {
        return GhostFidoCoreHIDBridgeStatus.invalidArgument.rawValue
    }
    guard ProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 15 else {
        return GhostFidoCoreHIDBridgeStatus.notReady.rawValue
    }
    guard processHasVirtualHIDEntitlement() else {
        return GhostFidoCoreHIDBridgeStatus.notPermitted.rawValue
    }
    return GhostFidoCoreHIDBridgeStatus.success.rawValue
}

/// Creates and activates one CoreHID virtual device.
@_cdecl("ghost_fido_corehid_create")
public func ghostFidoCoreHIDCreate(
    _ vendorID: UInt32,
    _ productID: UInt32,
    _ outputHandle: UnsafeMutablePointer<UnsafeMutableRawPointer?>
) -> Int32 {
    outputHandle.pointee = nil
    guard (1..<0xFFFF).contains(vendorID), (1..<0xFFFF).contains(productID) else {
        return GhostFidoCoreHIDBridgeStatus.invalidArgument.rawValue
    }

    guard #available(macOS 15.0, *) else {
        return GhostFidoCoreHIDBridgeStatus.notReady.rawValue
    }
    let readiness = ghostFidoCoreHIDCheckReadiness(vendorID, productID)
    guard readiness == GhostFidoCoreHIDBridgeStatus.success.rawValue else {
        return readiness
    }

    let handle = GhostFidoCoreHIDHandle()
    do {
        try waitForCoreHID {
            try await handle.device.activate(vendorID: vendorID, productID: productID)
        }
        outputHandle.pointee = Unmanaged.passRetained(handle).toOpaque()
        return GhostFidoCoreHIDBridgeStatus.success.rawValue
    } catch {
        return bridgeStatus(for: error).rawValue
    }
}

/// Sends one authenticator input report to the CoreHID virtual device.
@_cdecl("ghost_fido_corehid_send_input_report")
public func ghostFidoCoreHIDSendInputReport(
    _ rawHandle: UnsafeMutableRawPointer,
    _ report: UnsafePointer<UInt8>,
    _ reportLength: Int
) -> Int32 {
    guard reportLength == 64 else {
        return GhostFidoCoreHIDBridgeStatus.invalidArgument.rawValue
    }
    guard #available(macOS 15.0, *) else {
        return GhostFidoCoreHIDBridgeStatus.notReady.rawValue
    }

    let handle = Unmanaged<GhostFidoCoreHIDHandle>.fromOpaque(rawHandle).takeUnretainedValue()
    let data = Data(bytes: report, count: reportLength)
    do {
        try waitForCoreHID {
            try await handle.device.dispatchInputReport(data)
        }
        return GhostFidoCoreHIDBridgeStatus.success.rawValue
    } catch {
        return bridgeStatus(for: error).rawValue
    }
}

/// Receives one host output report, waiting for at most `timeoutMilliseconds`.
@_cdecl("ghost_fido_corehid_receive_output_report")
public func ghostFidoCoreHIDReceiveOutputReport(
    _ rawHandle: UnsafeMutableRawPointer,
    _ timeoutMilliseconds: UInt64,
    _ report: UnsafeMutablePointer<UInt8>,
    _ reportCapacity: Int,
    _ outputLength: UnsafeMutablePointer<Int>
) -> Int32 {
    outputLength.pointee = 0
    guard reportCapacity >= 64 else {
        return GhostFidoCoreHIDBridgeStatus.invalidArgument.rawValue
    }
    guard #available(macOS 15.0, *) else {
        return GhostFidoCoreHIDBridgeStatus.notReady.rawValue
    }

    let handle = Unmanaged<GhostFidoCoreHIDHandle>.fromOpaque(rawHandle).takeUnretainedValue()
    do {
        let data = try waitForCoreHID {
            try await handle.device.receiveOutputReport(timeoutMilliseconds: timeoutMilliseconds)
        }
        guard data.count == 64 else {
            return GhostFidoCoreHIDBridgeStatus.ioError.rawValue
        }
        data.copyBytes(to: report, count: data.count)
        outputLength.pointee = data.count
        return GhostFidoCoreHIDBridgeStatus.success.rawValue
    } catch {
        return bridgeStatus(for: error).rawValue
    }
}

/// Deactivates and releases one CoreHID virtual device.
@_cdecl("ghost_fido_corehid_destroy")
public func ghostFidoCoreHIDDestroy(_ rawHandle: UnsafeMutableRawPointer) -> Int32 {
    guard #available(macOS 15.0, *) else {
        _ = Unmanaged<GhostFidoCoreHIDHandle>.fromOpaque(rawHandle).takeRetainedValue()
        return GhostFidoCoreHIDBridgeStatus.notReady.rawValue
    }

    let handle = Unmanaged<GhostFidoCoreHIDHandle>.fromOpaque(rawHandle).takeRetainedValue()
    do {
        try waitForCoreHID {
            await handle.device.deactivate()
        }
        return GhostFidoCoreHIDBridgeStatus.success.rawValue
    } catch {
        return bridgeStatus(for: error).rawValue
    }
}
