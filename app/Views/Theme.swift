import SwiftUI

enum Brand {
    // Cyan from the app icon's gradient (extended-srgb 0, 0.753, 0.910).
    static let tint = Color(red: 0.0, green: 0.753, blue: 0.910)
}

/// A titled rounded card container, with an optional trailing accessory on the title row.
struct Card<Content: View, Accessory: View>: View {
    var title: String?
    var systemImage: String?
    var fill: Bool
    @ViewBuilder var accessory: Accessory
    @ViewBuilder var content: Content

    init(_ title: String? = nil, systemImage: String? = nil, fill: Bool = false,
         @ViewBuilder accessory: () -> Accessory = { EmptyView() },
         @ViewBuilder content: () -> Content) {
        self.title = title
        self.systemImage = systemImage
        self.fill = fill
        self.accessory = accessory()
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let title {
                HStack(spacing: 6) {
                    Label {
                        Text(title.uppercased())
                            .font(.caption2.weight(.semibold))
                            .foregroundStyle(.secondary)
                    } icon: {
                        if let systemImage {
                            Image(systemName: systemImage).font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                    .labelStyle(.titleAndIcon)
                    Spacer(minLength: 8)
                    accessory
                }
            }
            content
        }
        .padding(14)
        .frame(maxWidth: .infinity, maxHeight: fill ? .infinity : nil, alignment: .topLeading)
        .background(.background.secondary, in: .rect(cornerRadius: 12))
        .overlay(
            RoundedRectangle(cornerRadius: 12).strokeBorder(.separator, lineWidth: 0.5)
        )
    }
}

/// A small pill badge.
struct Pill: View {
    let text: String
    var color: Color = .secondary
    var body: some View {
        Text(text)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(color.opacity(0.15), in: .capsule)
            .foregroundStyle(color)
    }
}

extension SignStage {
    var title: String {
        switch self {
        case .preparing: "Preparing"
        case .authenticating: "Authenticating"
        case .registeringDevice: "Registering device"
        case .creatingCertificate: "Creating certificate"
        case .registeringApp: "Registering app"
        case .modifying: "Applying options"
        case .signing: "Signing"
        case .installing: "Installing"
        case .done: "Done"
        }
    }
}
