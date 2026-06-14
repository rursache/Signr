import XCTest
@testable import Signr

final class BridgeTests: XCTestCase {

    func testSyncBridgeReturnsRustValues() {
        XCTAssertEqual(coreVersion(), "0.1.0")
        // Proves the reused Plume crate (SignerMode Display) is linked and callable.
        XCTAssertEqual(signerModes(), ["Apple ID", "Adhoc", "No Modify"])
    }

    func testSelfTestExercisesAsyncCallbackAndProgress() async throws {
        let engine = SignrEngine(dataDir: NSTemporaryDirectory())
        let recorder = Recorder()
        let tfa = StubTwoFactor(code: "123456", recorder: recorder)
        let progress = StubProgress(recorder: recorder)

        let echoed = try await engine.selfTest(tfa: tfa, observer: progress)

        XCTAssertEqual(echoed, "123456", "Rust should return the Swift-provided 2FA code")
        XCTAssertTrue(recorder.twoFactorAsked, "Rust should have awaited the Swift 2FA callback")
        XCTAssertTrue(recorder.stages.contains(.done), "progress stream should reach .done")
        XCTAssertFalse(recorder.logs.isEmpty, "log lines should stream from Rust")
    }

    func testSignOptionsRoundTripsThroughFFI() {
        var options = SignOptions.empty
        options.customBundleId = "ro.randusoft.demo"
        options.tweaks = ["/tmp/a.dylib", "/tmp/b.deb"]
        options.enableEllekit = true
        // Records crossing the boundary keep their values (Equatable check).
        XCTAssertEqual(options.customBundleId, "ro.randusoft.demo")
        XCTAssertEqual(options.tweaks.count, 2)
        XCTAssertTrue(options.enableEllekit)
    }

    func testFreshEngineHasNoAccount() {
        let engine = SignrEngine(dataDir: NSTemporaryDirectory() + "signr-empty-\(UUID().uuidString)")
        XCTAssertNil(engine.currentAccount())
    }
}

// MARK: - Test doubles

final class Recorder: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var twoFactorAsked = false
    private(set) var stages: [SignStage] = []
    private(set) var logs: [String] = []

    func markTwoFactor() { lock.withLock { twoFactorAsked = true } }
    func record(stage: SignStage) { lock.withLock { stages.append(stage) } }
    func record(log: String) { lock.withLock { logs.append(log) } }
}

final class StubTwoFactor: TwoFactorProvider, @unchecked Sendable {
    let code: String
    let recorder: Recorder
    init(code: String, recorder: Recorder) { self.code = code; self.recorder = recorder }
    func provideTwoFactor(request: TwoFactorRequest) async throws -> TwoFactorResponse {
        recorder.markTwoFactor()
        return .code(code: code)
    }
}

final class StubProgress: ProgressObserver, @unchecked Sendable {
    let recorder: Recorder
    init(recorder: Recorder) { self.recorder = recorder }
    func onStage(stage: SignStage, percent: Double, message: String) { recorder.record(stage: stage) }
    func onLog(line: String) { recorder.record(log: line) }
}
