import SwiftUI

/// Explains why Apple sign-in is paused or risky and offers the way out
struct AccountSafetyNotice: View {
    @Environment(AppModel.self) private var model
    var appleID: String?
    /// The sign-in sheet asks for the remote anisette opt-in inline, elsewhere it links to Settings
    var inlineConsent = false

    private static let remoteWarning = """
        This Mac can't generate anisette data itself, so Apple sign-in has to go through a remote anisette server
        Apple has been locking Apple IDs that log in this way (-20209), so use a dedicated Apple ID instead of your main one
        """

    var body: some View {
        if let block = model.activeBlock(for: appleID) {
            notice(block.message, systemImage: "lock.fill", color: .red) {
                switch block {
                case .accountLocked:
                    Link("Open iForgot", destination: URL(string: "https://iforgot.apple.com")!)
                    Button("I've unlocked it") { model.clearAccountLock() }
                case .anisetteRejected:
                    SettingsLink { Text("Anisette Settings") }
                }
            }
        } else if model.hasNativeAnisette == false && (inlineConsent || !model.allowRemoteAnisette) {
            notice(Self.remoteWarning, systemImage: "exclamationmark.shield.fill", color: .orange) {
                if inlineConsent {
                    Toggle("Use a remote anisette server", isOn: Binding(
                        get: { model.allowRemoteAnisette },
                        set: { model.allowRemoteAnisette = $0 }))
                        .toggleStyle(.checkbox)
                } else {
                    SettingsLink { Text("Anisette Settings") }
                }
            }
        }
    }

    private func notice<Actions: View>(_ text: String, systemImage: String, color: Color,
                                       @ViewBuilder actions: () -> Actions) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label {
                Text(text).fixedSize(horizontal: false, vertical: true)
            } icon: {
                Image(systemName: systemImage).foregroundStyle(color)
            }
            HStack(spacing: 14) { actions() }
                .buttonStyle(.link)
        }
        .font(.caption)
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(color.opacity(0.1), in: .rect(cornerRadius: 8))
    }
}
