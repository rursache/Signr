import SwiftUI
import UniformTypeIdentifiers
import AppKit

struct SignScreen: View {
    @Environment(AppModel.self) private var model

    @State private var ipaURL: URL?
    @State private var ipaIcon: NSImage?
    @State private var ipaInfo: IpaInfo?

    @State private var bundleID = ""
    @State private var displayName = ""
    @State private var version = ""
    @State private var tweaks: [URL] = []

    @State private var mainBinaryOnly = false
    @State private var ellekit = false
    @State private var sideloadBypass = false
    @State private var wildcardAppId = true
    @State private var fileSharing = false
    @State private var ipadFullscreen = false
    @State private var proMotion = false
    @State private var gameMode = false
    @State private var liquidGlass = false
    @State private var increasedMemoryLimit = false
    @State private var removeURLSchemes = false
    @State private var removeDeviceRestrictions = false
    @State private var lowerMinOS = false

    @State private var showIpaImporter = false
    @State private var showTweakImporter = false
    @State private var isDropTargeted = false
    @State private var tweakDropTargeted = false

    var body: some View {
        Group {
            if model.isSignedIn { content } else { signedOutState }
        }
        .navigationTitle("Sign & Install")
        .toolbarTitleDisplayMode(.inline)
    }

    private var content: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 14) {
                ipaPicker
                HStack(alignment: .top, spacing: 16) {
                    VStack(spacing: 14) {
                        optionsCard
                        consoleCard
                    }
                    .frame(maxWidth: .infinity)
                    tweaksCard
                        .frame(maxWidth: .infinity)
                }
                .frame(maxHeight: .infinity)
            }
            .padding(.horizontal, 22).padding(.top, 10).padding(.bottom, 10)
            .frame(maxWidth: 1240, maxHeight: .infinity)
            .frame(maxWidth: .infinity, alignment: .top)
            actionBar
        }
        .fileImporter(isPresented: $showIpaImporter,
                      allowedContentTypes: [UTType(filenameExtension: "ipa") ?? .data]) { result in
            if case .success(let url) = result { setIpa(url) }
        }
        .fileImporter(isPresented: $showTweakImporter,
                      allowedContentTypes: tweakTypes, allowsMultipleSelection: true) { result in
            if case .success(let urls) = result { addTweaks(urls) }
        }
    }

    // MARK: IPA picker / drop zone

    private var ipaPicker: some View {
        Button {
            showIpaImporter = true
        } label: {
            HStack(spacing: 14) {
                if let icon = ipaIcon {
                    Image(nsImage: icon)
                        .resizable().interpolation(.high)
                        .frame(width: 46, height: 46)
                        .clipShape(.rect(cornerRadius: 10))
                } else {
                    Image(systemName: ipaURL == nil ? "arrow.down.app" : "app.badge.checkmark")
                        .font(.system(size: 26))
                        .foregroundStyle(ipaURL == nil ? Color.secondary : Brand.tint)
                        .frame(width: 46, height: 46)
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text(ipaInfo?.name ?? ipaURL?.lastPathComponent ?? "Choose an .ipa")
                        .font(.headline).lineLimit(1)
                    if ipaURL == nil {
                        Text("Click to browse, or drag an IPA here")
                            .font(.caption).foregroundStyle(.secondary)
                    } else if let info = ipaInfo {
                        HStack(spacing: 6) {
                            if let v = info.version { Pill(text: "v\(v)", color: Brand.tint) }
                            if let f = info.deviceFamily { Pill(text: f) }
                            if let m = info.minOs { Pill(text: "iOS \(m)+") }
                            if let sdk = info.sdkVersion { Pill(text: "SDK \(sdk)") }
                            if let size = ipaURL?.fileSizeString { Pill(text: size) }
                        }
                    } else if let size = ipaURL?.fileSizeString {
                        Text(size).font(.caption).foregroundStyle(.secondary)
                    }
                }
                Spacer()
                if ipaURL != nil {
                    Image(systemName: "xmark.circle.fill")
                        .font(.title3)
                        .foregroundStyle(.tertiary)
                        .onTapGesture { clearIpa() }
                }
            }
            .padding(13)
            .frame(maxWidth: .infinity)
            .background(
                RoundedRectangle(cornerRadius: 14)
                    .fill(isDropTargeted ? AnyShapeStyle(Brand.tint.opacity(0.12))
                                         : AnyShapeStyle(.background.secondary))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 14)
                    .strokeBorder(isDropTargeted ? Brand.tint : Color(nsColor: .separatorColor),
                                  style: StrokeStyle(lineWidth: isDropTargeted ? 1.5 : 0.5,
                                                     dash: ipaURL == nil ? [6] : []))
            )
        }
        .buttonStyle(.plain)
        .dropDestination(for: URL.self) { urls, _ in
            guard let url = urls.first(where: { $0.pathExtension.lowercased() == "ipa" }) ?? urls.first else { return false }
            setIpa(url)
            return true
        } isTargeted: { isDropTargeted = $0 }
    }

    // MARK: App options

    /// Free (Personal Team) accounts can't use wildcard App IDs, so they always get the
    /// team-id suffix and the wildcard option is hidden.
    private var isFreeTier: Bool { model.account?.tier == "Free" }

    private var optionsCard: some View {
        Card("App options", systemImage: "slider.horizontal.3") {
            labeledField("Bundle Identifier",
                         ipaInfo?.bundleId ?? "keep original", text: $bundleID)
            labeledField("Display Name", ipaInfo?.name ?? "keep original", text: $displayName)
            labeledField("Version", ipaInfo?.version ?? "keep original", text: $version)
            if !isFreeTier {
                Divider().padding(.vertical, 2)
                featureToggle("Wildcard App ID", "asterisk", $wildcardAppId,
                              subtitle: "No App ID registered in your dev account")
            }
        }
        .disabled(ipaURL == nil)
    }

    private var consoleCard: some View {
        Card("Console", systemImage: "terminal", fill: true, accessory: {
            Button { model.log.removeAll() } label: {
                Label("Clear", systemImage: "trash").font(.caption)
            }
            .buttonStyle(.borderless)
            .disabled(model.log.isEmpty)
        }) {
            if model.log.isEmpty {
                Text("Live output appears here while signing and installing.")
                    .font(.caption).foregroundStyle(.tertiary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .center)
                    .multilineTextAlignment(.center)
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        VStack(alignment: .leading, spacing: 3) {
                            ForEach(model.log.suffix(120)) { line in
                                consoleLine(line).id(line.id)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                    .onChange(of: model.log.count) {
                        if let last = model.log.last { proxy.scrollTo(last.id, anchor: .bottom) }
                    }
                }
            }
        }
    }

    private func consoleLine(_ line: LogLine) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Image(systemName: lineIcon(line.kind)).font(.caption2).foregroundStyle(lineColor(line.kind))
            Text(line.text).font(.caption.monospaced())
                .foregroundStyle(line.kind == .error ? Color.red : .primary)
            Spacer(minLength: 0)
        }
    }

    private func lineIcon(_ kind: LogLine.Kind) -> String {
        switch kind {
        case .info: "chevron.right"
        case .success: "checkmark"
        case .error: "xmark"
        }
    }
    private func lineColor(_ kind: LogLine.Kind) -> Color {
        switch kind {
        case .info: .secondary
        case .success: .green
        case .error: .red
        }
    }

    // MARK: Tweaks & toggles

    private var tweaksCard: some View {
        Card("Tweaks & options", systemImage: "wand.and.stars", fill: true, accessory: {
            Button { showTweakImporter = true } label: {
                Label("Add", systemImage: "plus").font(.caption)
            }
            .buttonStyle(.borderless)
        }) {
            tweakList
            Divider().padding(.vertical, 2)
            toggleGroup("Tweak runtime") {
                featureToggle("ElleKit runtime", "wand.and.stars", $ellekit,
                              subtitle: "Substrate-compatible, hosts injected tweaks")
                    .disabled(true)
                featureToggle("Sideload bypass", "eye.slash", $sideloadBypass,
                              subtitle: "Hides sideloading dylibs and the rest of the changes from apps")
            }
            toggleGroup("Capabilities") {
                featureToggle("Drop all extensions, widgets & watch app", "app.dashed", $mainBinaryOnly)
                featureToggle("File sharing (Files app)", "folder", $fileSharing)
                featureToggle("iPad fullscreen", "ipad.landscape", $ipadFullscreen)
                featureToggle("ProMotion (120 Hz)", "speedometer", $proMotion)
                featureToggle("Game mode", "gamecontroller", $gameMode)
                featureToggle("Liquid Glass", "circle.hexagongrid.fill", $liquidGlass)
                featureToggle("Increased memory limit", "memorychip", $increasedMemoryLimit)
                featureToggle("Lower minimum iOS", "arrow.down.to.line.compact", $lowerMinOS)
                featureToggle("Remove device restrictions", "iphone.slash", $removeDeviceRestrictions)
                featureToggle("Remove URL schemes", "link", $removeURLSchemes)
            }
        }
        // ElleKit is auto-managed: on when a tweak is present or bypass is enabled (bypass
        // links Substrate, so it needs ElleKit), off + locked when there's nothing to host.
        .onChange(of: tweaks.isEmpty) { _, isEmpty in
            if !isEmpty { ellekit = true } else if !sideloadBypass { ellekit = false }
        }
        .onChange(of: sideloadBypass) { _, on in
            if on { ellekit = true } else if tweaks.isEmpty { ellekit = false }
        }
    }

    @ViewBuilder
    private func toggleGroup<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            Text(title.uppercased())
                .font(.caption2.weight(.semibold)).foregroundStyle(.secondary)
            content()
        }
    }

    private func featureToggle(_ title: String, _ systemImage: String, _ isOn: Binding<Bool>,
                               subtitle: String? = nil) -> some View {
        HStack(spacing: 10) {
            Image(systemName: systemImage).foregroundStyle(.secondary).frame(width: 20)
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.callout)
                if let subtitle {
                    Text(subtitle).font(.caption2).foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 12)
            Toggle("", isOn: isOn).labelsHidden().toggleStyle(.switch)
        }
        .frame(maxWidth: .infinity)
    }

    private var tweakList: some View {
        VStack(alignment: .leading, spacing: 8) {
            if tweaks.isEmpty {
                Text("Drag files here, or click Add  ·  .dylib .deb .framework .bundle .appex")
                    .font(.caption2).foregroundStyle(.tertiary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 8)
            } else if tweaks.count <= 3 {
                ForEach(tweaks, id: \.self) { tweakRow($0) }
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(tweaks, id: \.self) { tweakRow($0) }
                    }
                    .padding(.trailing, 12)   // keep the delete buttons clear of the scrollbar
                }
                .frame(height: 86)
            }
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(tweakDropTargeted ? AnyShapeStyle(Brand.tint.opacity(0.10)) : AnyShapeStyle(.clear))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(tweakDropTargeted ? Brand.tint : Color(nsColor: .separatorColor),
                              style: StrokeStyle(lineWidth: tweakDropTargeted ? 1.5 : 0.5, dash: [5]))
        )
        .dropDestination(for: URL.self) { urls, _ in
            let valid = urls.filter { isTweakFile($0) }
            guard !valid.isEmpty else { return false }
            addTweaks(valid)
            return true
        } isTargeted: { tweakDropTargeted = $0 }
    }

    private func tweakRow(_ url: URL) -> some View {
        HStack {
            Image(systemName: "puzzlepiece.extension").foregroundStyle(Brand.tint)
            Text(url.lastPathComponent).font(.caption).lineLimit(1)
            Spacer()
            Button { tweaks.removeAll { $0 == url } } label: {
                Image(systemName: "minus.circle.fill").foregroundStyle(.tertiary)
            }.buttonStyle(.plain)
        }
    }

    // MARK: Banners + action bar

    private func resultBanner(_ signed: SignedApp) -> some View {
        Label {
            VStack(alignment: .leading, spacing: 2) {
                Text(signed.outputPath == nil ? "Installed successfully" : "Exported signed IPA")
                    .font(.callout.weight(.medium))
                if let out = signed.outputPath {
                    Text(out).font(.caption2.monospaced()).foregroundStyle(.secondary).lineLimit(1)
                }
            }
        } icon: {
            Image(systemName: "checkmark.seal.fill").foregroundStyle(.green)
        }
        .padding(12).frame(maxWidth: .infinity, alignment: .leading)
        .background(.green.opacity(0.1), in: .rect(cornerRadius: 10))
    }

    private func errorBanner(_ message: String) -> some View {
        Label(message, systemImage: "exclamationmark.triangle.fill")
            .font(.callout).foregroundStyle(.red)
            .padding(12).frame(maxWidth: .infinity, alignment: .leading)
            .background(.red.opacity(0.1), in: .rect(cornerRadius: 10))
    }

    private var actionBar: some View {
        HStack(spacing: 14) {
            if model.isWorking {
                ProgressView(value: model.progress).frame(width: 180)
                Text(model.isCancelling
                     ? "Cancelling…"
                     : "\(model.stage?.title ?? "Working") · \(Int(model.progress * 100))%")
                    .font(.caption.monospacedDigit()).foregroundStyle(.secondary).lineLimit(1)
                Button(role: .cancel) { model.cancel() } label: {
                    Label(model.isCancelling ? "Cancelling…" : "Cancel", systemImage: "stop.fill")
                }
                .disabled(model.isCancelling)
            } else {
                destinationSummary
            }
            Spacer()
            Button {
                guard let ipa = ipaURL else { return }
                model.signAndInstall(ipa: ipa, options: buildOptions())
            } label: {
                Label(model.isExporting ? "Sign & Export" : "Sign & Install", systemImage: "signature")
                    .frame(minWidth: 140)
            }
            .controlSize(.large)
            .buttonStyle(.borderedProminent)
            .disabled(ipaURL == nil || model.isWorking)
        }
        .padding(.horizontal, 24).padding(.vertical, 12)
        .background(.bar)
    }

    @ViewBuilder
    private var destinationSummary: some View {
        if let device = model.selectedDevice {
            Label("Install to \(device.name)", systemImage: device.isMac ? "macbook" : "iphone.gen3")
                .font(.caption).foregroundStyle(.secondary)
        } else {
            Label("Export a signed .ipa (no device selected)", systemImage: "square.and.arrow.up")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private var signedOutState: some View {
        ContentUnavailableView {
            Label("Sign in to start", systemImage: "person.badge.key")
        } description: {
            Text("Connect your Apple ID in the sidebar to request a certificate and sign apps.")
        } actions: {
            Button("Sign in with Apple ID") { model.showSignIn = true }
                .buttonStyle(.borderedProminent)
        }
        .navigationTitle("Sign & Install")
    }

    // MARK: Helpers

    private var tweakTypes: [UTType] {
        ["dylib", "deb", "framework", "bundle", "appex"].compactMap { UTType(filenameExtension: $0) } + [.data]
    }

    private func addTweaks(_ urls: [URL]) {
        tweaks.append(contentsOf: urls.filter { !tweaks.contains($0) })
    }

    private func clearIpa() {
        ipaURL = nil
        ipaIcon = nil
        ipaInfo = nil
        displayName = ""
        version = ""
    }

    private func setIpa(_ url: URL) {
        ipaURL = url
        model.errorMessage = nil
        model.lastSigned = nil
        ipaInfo = nil
        ipaIcon = nil
        Task { @MainActor in
            let info = await model.ipaInfo(for: url)
            ipaInfo = info
            if let info {
                if displayName.isEmpty, let name = info.name { displayName = name }
                if version.isEmpty, let v = info.version { version = v }
            }
            if let data = await model.ipaIconData(for: url) {
                ipaIcon = NSImage(data: data)
            }
        }
    }

    private func labeledField(_ title: String, _ placeholder: String, text: Binding<String>) -> some View {
        HStack {
            Text(title).font(.callout).frame(width: 130, alignment: .leading)
            TextField(placeholder, text: text).textFieldStyle(.roundedBorder)
        }
    }

    private func isTweakFile(_ url: URL) -> Bool {
        ["dylib", "deb", "framework", "bundle", "appex"].contains(url.pathExtension.lowercased())
    }

    private func buildOptions() -> SignOptions {
        var o = SignOptions.empty
        o.customBundleId = bundleID.isEmpty ? nil : bundleID
        o.customName = displayName.isEmpty ? nil : displayName
        o.customVersion = version.isEmpty ? nil : version
        o.tweaks = tweaks.map { $0.path(percentEncoded: false) }
        o.mainBinaryOnly = mainBinaryOnly
        o.enableEllekit = ellekit
        o.enableSideloadBypass = sideloadBypass
        o.enableFileSharing = fileSharing
        o.enableIpadFullscreen = ipadFullscreen
        o.enableProMotion = proMotion
        o.enableGameMode = gameMode
        o.enableLiquidGlass = liquidGlass
        o.increasedMemoryLimit = increasedMemoryLimit
        o.removeUrlSchemes = removeURLSchemes
        o.removeUiSupportedDevices = removeDeviceRestrictions
        o.lowerMinOs = lowerMinOS
        o.wildcardAppId = wildcardAppId
        return o
    }
}

extension URL {
    var fileSizeString: String? {
        guard let size = try? resourceValues(forKeys: [.fileSizeKey]).fileSize else { return nil }
        return ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file)
    }
}
