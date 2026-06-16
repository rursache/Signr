import Foundation
import Observation
import AppKit
import UniformTypeIdentifiers
import CryptoKit

@MainActor
@Observable
final class AppModel {
    // Bridge info
    let version: String

    // Session
    var account: Account?
    var teams: [Team] = []
    var isSignedIn: Bool { account != nil }

    // Devices
    var devices: [DeviceInfo] = []
    var selectedDeviceID: String?
    var isLoadingDevices = false
    var deviceError: String?

    // Work state (shared by sign-in and sign-and-install)
    var isWorking = false
    var isCancelling = false
    var stage: SignStage?
    var progress: Double = 0
    var statusMessage = ""
    var log: [LogLine] = []
    var history: [HistoryEntry] = []
    var errorMessage: String?
    var lastSigned: SignedApp?

    // Sheets
    var showSignIn = false
    var showActivity = false

    // 2FA coordination
    var twoFactorPrompt = false
    var twoFactorRequest: TwoFactorRequest?
    var twoFactorCode = ""
    var twoFactorError: String?
    var twoFactorBusy = false
    private var twoFactorContinuation: CheckedContinuation<TwoFactorResponse, Error>?

    private let engine: SignrEngine
    private var deviceBridge: DeviceBridge?
    private var didAutoSelectDevice = false

    init() {
        let dir = AppModel.dataDirectory()
        engine = SignrEngine(dataDir: dir.path(percentEncoded: false))
        version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
            ?? coreVersion()
        account = engine.currentAccount()
        // Restore the last resolved tier + teams so the account card renders its final state
        // immediately, instead of flashing the half-populated version (no tier, no chevron)
        // until refreshTeams() returns from the network.
        if let acc = account, let (cached, cachedTeams) = AppModel.loadAccountCache(),
           cached.appleId == acc.appleId {
            account = cached
            teams = cachedTeams
        }
        loadHistory()
    }

    // MARK: - Persistence (opaque encrypted blobs in the app data directory)

    private static let accountCacheFile = "device.dat"
    private static let historyFile = "recents.dat"

    private static func dataFile(_ name: String) -> URL {
        dataDirectory().appendingPathComponent(name)
    }

    private struct CachedAccount: Codable {
        var appleId: String, teamName: String, teamId: String, tier: String
        var teams: [CachedTeam]
    }
    private struct CachedTeam: Codable { var id: String, name: String, tier: String }

    private static func loadAccountCache() -> (Account, [Team])? {
        guard let raw = try? Data(contentsOf: dataFile(accountCacheFile)) else { return nil }
        let json = DataCrypto.decrypt(raw) ?? raw
        guard let c = try? JSONDecoder().decode(CachedAccount.self, from: json) else { return nil }
        return (Account(appleId: c.appleId, teamName: c.teamName, teamId: c.teamId, tier: c.tier),
                c.teams.map { Team(id: $0.id, name: $0.name, tier: $0.tier) })
    }

    private func saveAccountCache() {
        let file = AppModel.dataFile(AppModel.accountCacheFile)
        guard let a = account else { try? FileManager.default.removeItem(at: file); return }
        let cache = CachedAccount(
            appleId: a.appleId, teamName: a.teamName, teamId: a.teamId, tier: a.tier,
            teams: teams.map { CachedTeam(id: $0.id, name: $0.name, tier: $0.tier) })
        if let data = try? JSONEncoder().encode(cache) {
            try? DataCrypto.encrypt(data).write(to: file, options: .atomic)
        }
    }

    private func loadHistory() {
        guard let raw = try? Data(contentsOf: AppModel.dataFile(AppModel.historyFile)) else { return }
        let json = DataCrypto.decrypt(raw) ?? raw
        if let h = try? JSONDecoder().decode([HistoryEntry].self, from: json) {
            history = h
        }
    }

    private func recordHistory(appName: String, bundleId: String, target: String,
                               success: Bool, detail: String) {
        history.insert(HistoryEntry(date: Date(), appName: appName, bundleId: bundleId,
                                    target: target, success: success, detail: detail), at: 0)
        if history.count > 100 { history.removeLast(history.count - 100) }
        if let data = try? JSONEncoder().encode(history) {
            try? DataCrypto.encrypt(data).write(to: AppModel.dataFile(AppModel.historyFile), options: .atomic)
        }
    }

    func clearHistory() {
        history.removeAll()
        try? FileManager.default.removeItem(at: AppModel.dataFile(AppModel.historyFile))
    }

    static func dataDirectory() -> URL {
        let base = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let dir = base.appendingPathComponent("Signr", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    /// Gravatar URL for an email, or nil if empty. `d=404` makes Gravatar return HTTP 404
    /// when there's no avatar, so the UI can fall back to the initial-letter circle.
    static func gravatarURL(for email: String, size: Int = 128) -> URL? {
        let normalized = email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !normalized.isEmpty else { return nil }
        let hash = Insecure.MD5.hash(data: Data(normalized.utf8))
            .map { String(format: "%02x", $0) }.joined()
        return URL(string: "https://www.gravatar.com/avatar/\(hash)?s=\(size)&d=404")
    }

    // MARK: - Auth

    func signIn(appleID: String, password: String) {
        guard !isWorking else { return }
        beginWork()
        let progress = makeObserver()
        let tfa = TwoFactorBridge(handler: { [weak self] request in
            guard let self else { throw CancellationError() }
            return try await self.requestTwoFactor(request)
        })
        Task {
            do {
                let account = try await engine.signIn(
                    appleId: appleID, password: password, tfa: tfa, observer: progress
                )
                self.account = account
                self.teams = engine.listTeams()
                self.saveAccountCache()
                self.showSignIn = false
                self.appendLog("Signed in to \(account.teamName)", .success)
            } catch {
                // Cancelling the 2FA sheet throws CancellationError — treat it as a quiet stop
                // rather than surfacing the raw "(Swift.CancellationError error 1.)" string.
                if AppModel.isCancellation(error) {
                    self.appendLog("Sign-in cancelled", .info)
                } else {
                    self.errorMessage = error.localizedDescription
                    self.appendLog(error.localizedDescription, .error)
                }
            }
            self.endWork()
        }
    }

    func signOut() {
        Task {
            await engine.signOut()
            account = nil
            teams = []
            saveAccountCache()
            appendLog("Signed out", .info)
        }
    }

    func selectTeam(_ teamID: String) {
        guard teamID != account?.teamId else { return }
        Task {
            do {
                account = try await engine.selectTeam(teamId: teamID)
                saveAccountCache()
                appendLog("Switched to team \(account?.teamName ?? "")", .info)
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }

    /// On launch, re-fetch teams so the picker and free/paid flag are accurate for a
    /// restored session. Best-effort — keeps the stored account if offline/expired.
    func refreshAccountOnLaunch() async {
        guard isSignedIn else { return }
        if let refreshed = try? await engine.refreshTeams() {
            account = refreshed
            teams = engine.listTeams()
            saveAccountCache()
        }
    }

    /// Read an IPA's Info.plist off the main thread.
    func ipaInfo(for url: URL) async -> IpaInfo? {
        await Task.detached {
            try? readIpaInfo(ipaPath: url.path(percentEncoded: false))
        }.value
    }

    /// Read the app's icon (normalized PNG) off the main thread.
    func ipaIconData(for url: URL) async -> Data? {
        await Task.detached {
            readIpaIcon(ipaPath: url.path(percentEncoded: false))
        }.value
    }

    // MARK: - Devices

    /// Begin live USB + WiFi device detection. Idempotent — Rust pushes the current set
    /// immediately, then on every connect/disconnect. Replaces manual polling.
    func startDeviceWatch() {
        guard deviceBridge == nil else { return }
        let bridge = DeviceBridge(onDevices: { [weak self] found in
            Task { @MainActor in self?.applyDevices(found) }
        })
        deviceBridge = bridge
        engine.startDeviceWatch(observer: bridge)
    }

    /// One-shot manual refresh (the sidebar's refresh button). The live watch keeps the
    /// list current on its own, but this re-reads device info on demand (e.g. after trust).
    func refreshDevices() async {
        isLoadingDevices = true
        deviceError = nil
        do {
            applyDevices(try await engine.listDevices())
        } catch {
            deviceError = error.localizedDescription
            devices = []
            isLoadingDevices = false
        }
    }

    private func applyDevices(_ found: [DeviceInfo]) {
        devices = found
        isLoadingDevices = false
        deviceError = nil

        if !didAutoSelectDevice {
            // First population: pick the first connected device (export when none).
            didAutoSelectDevice = true
            selectedDeviceID = found.first.map { String($0.deviceId) }
        } else if let sel = selectedDeviceID,
                  !found.contains(where: { String($0.deviceId) == sel }) {
            // The chosen device disconnected → fall back to the next one (or export).
            selectedDeviceID = found.first.map { String($0.deviceId) }
        }
    }

    /// Trust / re-pair a device so it can be installed to. The user taps "Trust" on the
    /// device when prompted; lockdown then saves a fresh pairing record.
    func pairDevice(_ deviceID: String) {
        Task {
            do {
                try await engine.pairDevice(deviceId: deviceID)
                appendLog("Paired device — re-reading info", .success)
                await refreshDevices()
            } catch {
                errorMessage = error.localizedDescription
                appendLog("Pairing failed: \(error.localizedDescription)", .error)
            }
        }
    }

    // MARK: - Sign

    /// The currently chosen device, or nil when exporting an .ipa.
    var selectedDevice: DeviceInfo? {
        devices.first { String($0.deviceId) == selectedDeviceID }
    }
    var isExporting: Bool { selectedDevice == nil }

    func signAndInstall(ipa: URL, options: SignOptions) {
        guard !isWorking else { return }
        beginWork()
        lastSigned = nil
        let observer = makeObserver()
        let deviceID = selectedDeviceID
        let targetName = selectedDevice?.name
        let fallbackName = ipa.deletingPathExtension().lastPathComponent
        Task {
            do {
                let signed = try await engine.signAndInstall(
                    ipaPath: ipa.path(percentEncoded: false),
                    options: options,
                    deviceId: deviceID,
                    observer: observer
                )
                // If the user hit Cancel just as the run completed, honor the cancel instead of
                // popping a success banner, a history row, and (on export) a blocking save panel
                // for a result they asked to abandon. Retrying just re-signs — install is idempotent.
                if self.isCancelling {
                    self.endWork()
                    self.appendLog("Cancelled", .info)
                    return
                }
                self.lastSigned = signed
                self.endWork()
                let installed = signed.outputPath == nil
                if installed {
                    self.appendLog("Installed to device", .success)
                } else {
                    self.promptExportSave(for: signed)
                }
                self.recordHistory(
                    appName: signed.displayName.isEmpty ? fallbackName : signed.displayName,
                    bundleId: signed.bundleId,
                    target: targetName ?? "Export",
                    success: true,
                    detail: installed ? "Installed to \(targetName ?? "device")" : "Exported signed IPA")
            } catch {
                // A user-initiated cancel is a clean stop, not a failure: don't surface a red
                // error banner or write a history row for it, just reset and let them retry.
                let wasCancelled = self.isCancelling || AppModel.isCancellation(error)
                self.endWork()
                if wasCancelled {
                    self.appendLog("Cancelled", .info)
                } else {
                    self.errorMessage = error.localizedDescription
                    self.appendLog(error.localizedDescription, .error)
                    self.recordHistory(
                        appName: options.customName ?? fallbackName,
                        bundleId: options.customBundleId ?? "",
                        target: targetName ?? "Export",
                        success: false,
                        detail: error.localizedDescription)
                }
            }
        }
    }

    /// After a successful export the signed IPA lives in a temp dir. Ask the user where to
    /// keep it and copy it there, updating the result banner to the saved location.
    private func promptExportSave(for signed: SignedApp) {
        guard let tempPath = signed.outputPath else { return }
        let suggested = signed.displayName.isEmpty
            ? URL(fileURLWithPath: tempPath).lastPathComponent
            : "\(signed.displayName).ipa"

        let panel = NSSavePanel()
        panel.title = "Save Signed IPA"
        panel.nameFieldStringValue = suggested
        panel.allowedContentTypes = [UTType(filenameExtension: "ipa") ?? .data]
        panel.canCreateDirectories = true

        guard panel.runModal() == .OK, let dest = panel.url else {
            appendLog("Signed IPA kept at \(tempPath)", .info)
            return
        }
        do {
            let fm = FileManager.default
            if fm.fileExists(atPath: dest.path(percentEncoded: false)) {
                try fm.removeItem(at: dest)
            }
            try fm.copyItem(at: URL(fileURLWithPath: tempPath), to: dest)
            lastSigned = SignedApp(bundleId: signed.bundleId, displayName: signed.displayName,
                                   outputPath: dest.path(percentEncoded: false))
            appendLog("Saved to \(dest.path(percentEncoded: false))", .success)
        } catch {
            errorMessage = error.localizedDescription
            appendLog("Save failed: \(error.localizedDescription)", .error)
        }
    }

    func cancel() {
        guard isWorking, !isCancelling else { return }
        isCancelling = true
        engine.cancel()
        appendLog("Cancelling…", .info)
    }

    /// True for a cancel that came back through the FFI as `SignrError.Cancelled` or a Swift
    /// `CancellationError`, so the completion handler can treat it as a clean stop.
    private static func isCancellation(_ error: Error) -> Bool {
        if let e = error as? SignrError, case .Cancelled = e { return true }
        return error is CancellationError
    }

    // MARK: - 2FA

    /// Called from the TwoFactorBridge (Rust thread → main actor). Suspends until the
    /// user submits a code or requests an SMS.
    func requestTwoFactor(_ request: TwoFactorRequest) async throws -> TwoFactorResponse {
        try await withCheckedThrowingContinuation { continuation in
            self.twoFactorRequest = request
            self.twoFactorCode = ""
            self.twoFactorError = nil
            self.twoFactorBusy = false
            self.twoFactorContinuation = continuation
            self.twoFactorPrompt = true
        }
    }

    func submitTwoFactor() {
        let code = twoFactorCode.trimmingCharacters(in: .whitespaces)
        guard !code.isEmpty, let continuation = twoFactorContinuation else { return }
        twoFactorBusy = true
        twoFactorContinuation = nil
        continuation.resume(returning: .code(code: code))
    }

    /// Ask Apple to (re)send the code by SMS. Rust will call back again with the SMS
    /// method so the user can then enter the texted code.
    func sendTwoFactorSms(phoneID: UInt32) {
        guard let continuation = twoFactorContinuation else { return }
        twoFactorBusy = true
        twoFactorError = nil
        twoFactorContinuation = nil
        continuation.resume(returning: .sendSms(phoneId: phoneID))
    }

    func cancelTwoFactor() {
        twoFactorPrompt = false
        twoFactorContinuation?.resume(throwing: CancellationError())
        twoFactorContinuation = nil
    }

    // MARK: - Helpers

    private func makeObserver() -> ProgressBridge {
        ProgressBridge(
            onStage: { [weak self] stage, pct, message in
                Task { @MainActor in self?.apply(stage: stage, pct: pct, message: message) }
            },
            onLog: { [weak self] line in
                Task { @MainActor in self?.appendLog(line, .info) }
            }
        )
    }

    private func beginWork() {
        isWorking = true
        errorMessage = nil
        statusMessage = ""
        progress = 0
        stage = nil
    }

    private func endWork() {
        isWorking = false
        isCancelling = false
        stage = nil
        progress = 0
        statusMessage = ""
        twoFactorPrompt = false
        twoFactorRequest = nil
        twoFactorBusy = false
    }

    private func apply(stage: SignStage, pct: Double, message: String) {
        // Ignore progress that lands after the user cancelled (or after the run ended): the
        // in-flight Rust future is being torn down and a late "Uploading… 90%" line would
        // otherwise print below "Cancelled".
        guard isWorking, !isCancelling else { return }
        self.stage = stage
        // Clamp to non-decreasing: the install phase interleaves a synthetic "creep" with real
        // installd events, which can land below the creep the bar already reached.
        self.progress = max(self.progress, pct)
        if !message.isEmpty {
            statusMessage = message
            // Skip consecutive duplicates so the repeated "Installing on device…" creep ticks
            // (same text, advancing percent) log a single line.
            if log.last?.text != message {
                appendLog(message, .info)
            }
        }
    }

    private func appendLog(_ text: String, _ kind: LogLine.Kind) {
        log.append(LogLine(text: text, kind: kind))
        if log.count > 500 { log.removeFirst(log.count - 500) }
    }
}

struct LogLine: Identifiable {
    enum Kind { case info, success, error }
    let id = UUID()
    let text: String
    let kind: Kind
}

/// A persisted record of one sign + install (or export) run.
struct HistoryEntry: Codable, Identifiable {
    var id = UUID()
    var date: Date
    var appName: String
    var bundleId: String
    var target: String
    var success: Bool
    var detail: String
}
