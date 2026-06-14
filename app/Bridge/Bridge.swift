import Foundation

/// Implements the Rust `ProgressObserver` foreign trait. Rust calls these from its
/// own threads, so the closure hops to the main actor before touching UI state.
final class ProgressBridge: ProgressObserver, @unchecked Sendable {
    private let onStageCb: @Sendable (SignStage, Double, String) -> Void
    private let onLogCb: @Sendable (String) -> Void

    init(
        onStage: @escaping @Sendable (SignStage, Double, String) -> Void,
        onLog: @escaping @Sendable (String) -> Void
    ) {
        self.onStageCb = onStage
        self.onLogCb = onLog
    }

    func onStage(stage: SignStage, percent: Double, message: String) {
        onStageCb(stage, percent, message)
    }

    func onLog(line: String) {
        onLogCb(line)
    }
}

/// Implements the Rust `DeviceObserver` foreign trait. Rust pushes the full device list
/// from its watch thread; the closure hops to the main actor to refresh the sidebar.
final class DeviceBridge: DeviceObserver, @unchecked Sendable {
    private let onDevicesCb: @Sendable ([DeviceInfo]) -> Void

    init(onDevices: @escaping @Sendable ([DeviceInfo]) -> Void) {
        self.onDevicesCb = onDevices
    }

    func onDevices(devices: [DeviceInfo]) {
        onDevicesCb(devices)
    }
}

/// Implements the Rust `TwoFactorProvider` foreign trait. Rust awaits this mid-login;
/// we suspend until the user submits a code (or requests an SMS) in the SwiftUI sheet.
final class TwoFactorBridge: TwoFactorProvider, @unchecked Sendable {
    private let handler: @Sendable (TwoFactorRequest) async throws -> TwoFactorResponse

    init(handler: @escaping @Sendable (TwoFactorRequest) async throws -> TwoFactorResponse) {
        self.handler = handler
    }

    func provideTwoFactor(request: TwoFactorRequest) async throws -> TwoFactorResponse {
        try await handler(request)
    }
}
