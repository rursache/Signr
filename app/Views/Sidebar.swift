import SwiftUI

struct Sidebar: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    AccountCard()
                    if model.isSignedIn { DestinationSection() }
                }
                .padding(14)
            }
            Spacer(minLength: 0)
            Divider()
            historyButton
        }
    }

    private var header: some View {
        HStack(spacing: 9) {
            Image(systemName: "signature")
                .font(.system(size: 18, weight: .bold))
                .foregroundStyle(Brand.tint)
            Text("Signr").font(.title3.bold())
            Spacer()
            Text("v\(model.version)")
                .font(.caption2.monospaced()).foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 16).padding(.top, 14).padding(.bottom, 10)
    }

    private var historyButton: some View {
        Button { model.showActivity = true } label: {
            HStack(spacing: 9) {
                Image(systemName: "clock.arrow.circlepath").frame(width: 20)
                Text("History").font(.callout)
                Spacer()
                if !model.history.isEmpty {
                    Text("\(model.history.count)")
                        .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                        .padding(.horizontal, 6).padding(.vertical, 1)
                        .background(.quaternary, in: .capsule)
                }
            }
            .padding(.horizontal, 14).padding(.vertical, 11)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Destination (device selection)

struct DestinationSection: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("DESTINATION")
                    .font(.caption2.weight(.semibold)).foregroundStyle(.secondary)
                Spacer()
                Button {
                    Task { await model.refreshDevices() }
                } label: {
                    if model.isLoadingDevices {
                        ProgressView().controlSize(.mini)
                    } else {
                        Image(systemName: "arrow.clockwise")
                    }
                }
                .buttonStyle(.borderless).font(.caption)
                .help("Refresh devices")
            }

            VStack(spacing: 3) {
                ForEach(model.devices, id: \.deviceId) { d in
                    deviceRow(d)
                }
                if !model.devices.isEmpty {
                    Divider().padding(.vertical, 3)
                }
                row(id: nil, title: "Export signed .ipa",
                    subtitle: Text("save without installing"), icon: "square.and.arrow.up")
            }

            if model.devices.isEmpty {
                Text("Connect an iPhone or iPad over USB or WiFi — it shows up automatically.")
                    .font(.caption2).foregroundStyle(.tertiary)
            }
        }
    }

    /// A device entry: the selectable row plus a trailing Trust / re-pair button.
    private func deviceRow(_ d: DeviceInfo) -> some View {
        HStack(spacing: 2) {
            row(id: String(d.deviceId),
                title: d.name.isEmpty ? "iOS device" : d.name,
                subtitle: deviceSubtitle(d),
                icon: d.isMac ? "macbook" : "iphone.gen3")
            Button {
                model.pairDevice(String(d.deviceId))
            } label: {
                Image(systemName: "lock.shield")
                    .font(.caption).foregroundStyle(.secondary)
                    .frame(width: 26, height: 26).contentShape(.rect)
            }
            .buttonStyle(.plain)
            .help("Trust / re-pair this device")
        }
    }

    /// Subtitle with the USB / WiFi link symbol sitting inline before the model + iOS version
    private func deviceSubtitle(_ d: DeviceInfo) -> Text {
        var parts: [String] = []
        if let v = d.osVersion, !v.isEmpty { parts.append("iOS \(v)") }
        if let pt = d.productType, !pt.isEmpty { parts.append(pt) }
        if parts.isEmpty { parts.append(d.udid.isEmpty ? "id \(d.deviceId)" : d.udid) }
        let label = Text(parts.joined(separator: " · "))
        guard let symbol = linkSymbol(d.link) else { return label }
        return Text(Image(systemName: symbol)) + Text(" · ") + label
    }

    private func linkSymbol(_ link: DeviceLink) -> String? {
        switch link {
        case .usb: return "cable.connector"
        case .wifi: return "wifi"
        case .unknown: return nil
        }
    }

    private func row(id: String?, title: String, subtitle: Text, icon: String) -> some View {
        let selected = model.selectedDeviceID == id
        return Button {
            model.selectedDeviceID = id
        } label: {
            HStack(spacing: 9) {
                Image(systemName: icon)
                    .foregroundStyle(selected ? Brand.tint : Color.secondary).frame(width: 20)
                VStack(alignment: .leading, spacing: 1) {
                    Text(title).font(.callout).lineLimit(1)
                    subtitle.font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer(minLength: 4)
                if selected {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(Brand.tint)
                }
            }
            .padding(.vertical, 6).padding(.horizontal, 8)
            .background(selected ? AnyShapeStyle(Brand.tint.opacity(0.12)) : AnyShapeStyle(.clear),
                        in: .rect(cornerRadius: 8))
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Account card

struct AccountCard: View {
    @Environment(AppModel.self) private var model
    @State private var emailHidden = false

    var body: some View {
        if let account = model.account {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 10) {
                    avatar(for: account.appleId)
                    accountDropdown(account)
                    Spacer(minLength: 8)
                    Button { emailHidden.toggle() } label: {
                        Image(systemName: emailHidden ? "eye.slash" : "eye")
                            .font(.caption2).foregroundStyle(.tertiary).contentShape(.rect)
                    }
                    .buttonStyle(.plain)
                    .help(emailHidden ? "Show email" : "Hide email")
                }
                HStack(spacing: 6) {
                    if !account.tier.isEmpty {
                        Pill(text: tierLabel(account.tier), color: tierColor(account.tier))
                    }
                    if !account.teamId.isEmpty {
                        Pill(text: account.teamId)
                    }
                    Spacer()
                    Button("Sign out") { model.signOut() }
                        .buttonStyle(.plain).font(.caption).foregroundStyle(.secondary)
                }
            }
            .padding(12)
            .background(.background.secondary, in: .rect(cornerRadius: 10))
        } else {
            Button {
                model.showSignIn = true
            } label: {
                HStack(spacing: 10) {
                    Image(systemName: "person.crop.circle.badge.plus")
                        .font(.title3).foregroundStyle(Brand.tint)
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Sign in").font(.callout.weight(.medium))
                        Text("with your Apple ID").font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                }
                .padding(12)
                .frame(maxWidth: .infinity)
                .background(.background.secondary, in: .rect(cornerRadius: 10))
            }
            .buttonStyle(.plain)
        }
    }

    /// Account dropdown next to the avatar: email over team name, with the up/down chevron
    /// bracketing both lines. Switches teams when the account has more than one.
    @ViewBuilder
    private func accountDropdown(_ account: Account) -> some View {
        if model.teams.count > 1 {
            Menu {
                ForEach(model.teams, id: \.id) { team in
                    Button {
                        model.selectTeam(team.id)
                    } label: {
                        if team.id == account.teamId {
                            Label(teamLabel(team), systemImage: "checkmark")
                        } else {
                            Text(teamLabel(team))
                        }
                    }
                }
            } label: {
                accountDropdownLabel(account, selectable: true)
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
        } else {
            accountDropdownLabel(account, selectable: false)
        }
    }

    private func accountDropdownLabel(_ account: Account, selectable: Bool) -> some View {
        HStack(spacing: 7) {
            if selectable {
                Image(systemName: "chevron.up.chevron.down")
                    .font(.system(size: 16)).foregroundStyle(Brand.tint)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(emailHidden ? censoredEmail(account.appleId) : account.appleId.lowercased())
                    .font(.callout.weight(.medium)).lineLimit(1)
                Text(account.teamName)
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
        }
        .contentShape(.rect)
    }

    private func teamLabel(_ team: Team) -> String {
        "\(team.name) · \(team.tier) · \(team.id)"
    }

    private func tierLabel(_ tier: String) -> String {
        switch tier {
        case "Free": "Free · 7-day"
        case "Paid": "Developer"
        default: tier
        }
    }

    private func tierColor(_ tier: String) -> Color {
        switch tier {
        case "Free": .orange
        case "Personal": .blue
        default: .green
        }
    }

    @ViewBuilder
    /// Mask an email for the hidden state, keeping the shape: `user@example.com` -> `u•••@•••••••.com`.
    private func censoredEmail(_ email: String) -> String {
        let lower = email.lowercased()
        guard let at = lower.firstIndex(of: "@") else {
            return String(repeating: "•", count: max(lower.count, 6))
        }
        let local = String(lower[lower.startIndex..<at])
        let domain = String(lower[lower.index(after: at)...])
        let maskedLocal = local.isEmpty
            ? ""
            : String(local.first!) + String(repeating: "•", count: max(local.count - 1, 1))
        guard let dot = domain.lastIndex(of: ".") else {
            return "\(maskedLocal)@\(String(repeating: "•", count: max(domain.count, 1)))"
        }
        let name = String(repeating: "•", count: max(domain.distance(from: domain.startIndex, to: dot), 1))
        return "\(maskedLocal)@\(name)\(domain[dot...])"
    }

    @ViewBuilder
    private func avatar(for email: String) -> some View {
        let initial = String(email.first ?? "?").uppercased()
        Group {
            if let url = AppModel.gravatarURL(for: email) {
                AsyncImage(url: url) { phase in
                    if case .success(let image) = phase {
                        image.resizable().interpolation(.high)
                    } else {
                        initialAvatar(initial)
                    }
                }
            } else {
                initialAvatar(initial)
            }
        }
        .frame(width: 34, height: 34)
        .clipShape(.circle)
    }

    private func initialAvatar(_ initial: String) -> some View {
        Text(initial)
            .font(.headline)
            .foregroundStyle(.white)
            .frame(width: 34, height: 34)
            .background(Brand.tint.gradient, in: .circle)
    }
}
