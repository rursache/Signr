import SwiftUI

struct SettingsView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        Form {
            Section {
                LabeledContent("This Mac") { nativeStatus }
                Toggle("Allow anisette fallback", isOn: $model.allowRemoteAnisette)
                TextField("Server", text: $model.anisetteServerURL,
                          prompt: Text("Default (ani.sidestore.app)"))
                    .disabled(!model.allowRemoteAnisette)
                if !model.anisetteServerURLIsValid {
                    Text("Enter a full URL starting with https://")
                        .font(.caption).foregroundStyle(.red)
                }
            } header: {
                Text("Anisette")
            } footer: {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Apple sign-in needs anisette data, macOS 26 and earlier generate it locally which is the safe path")
                    Text("On macOS 27 it has to come from a remote server, and Apple has been locking Apple IDs (-20209) that log in through public ones")
                    Text("Only turn this on with a dedicated Apple ID and stop after a failed login instead of retrying")
                    Text("The fallback uses emulated ADI instead of the server when libstoreservicescore.so is in Signr's anisette folder")
                }
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }
        }
        .formStyle(.grouped)
        .scrollDisabled(true)
        .frame(width: 500, height: 320)
    }

    @ViewBuilder
    private var nativeStatus: some View {
        switch model.hasNativeAnisette {
        case true?:
            Label("Generates its own anisette", systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green)
        case false?:
            Label("Can't generate anisette locally", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
        case nil:
            ProgressView().controlSize(.small)
        }
    }
}
