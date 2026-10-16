import SwiftUI

struct SettingsView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        Form {
            Section {
                LabeledContent("This Mac") { nativeStatus }
                Toggle("Allow anisette fallback", isOn: $model.allowRemoteAnisette)
                Picker("Server", selection: $model.anisetteServerChoice) {
                    ForEach(AnisetteServerChoice.allCases) { choice in
                        Text(choice.label).tag(choice)
                    }
                }
                .pickerStyle(.menu)
                .disabled(!model.allowRemoteAnisette)
                if model.anisetteServerChoice == .custom {
                    TextField("Custom URL", text: $model.anisetteServerURL,
                              prompt: Text("https://anisette.example.com"))
                        .disabled(!model.allowRemoteAnisette)
                    if !model.anisetteServerURLIsValid {
                        Text("Enter a full URL starting with https://")
                            .font(.caption).foregroundStyle(.red)
                    }
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
        .frame(width: 500, height: height)
    }

    // The form doesn't scroll, so grow the window for the custom URL row and its hint
    private var height: CGFloat {
        guard model.anisetteServerChoice == .custom else { return 320 }
        return model.anisetteServerURLIsValid ? 360 : 395
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
