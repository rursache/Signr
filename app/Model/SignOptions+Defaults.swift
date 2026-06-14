import Foundation

extension SignOptions {
    /// An all-empty options value (UniFFI records have no default initializer).
    static var empty: SignOptions {
        SignOptions(
            customBundleId: nil,
            customName: nil,
            customVersion: nil,
            customIconPath: nil,
            tweaks: [],
            mainBinaryOnly: false,
            enableFileSharing: false,
            enableIpadFullscreen: false,
            enableProMotion: false,
            enableGameMode: false,
            enableLiquidGlass: false,
            increasedMemoryLimit: false,
            enableEllekit: false,
            enableSideloadBypass: false,
            removeUrlSchemes: false,
            removeUiSupportedDevices: false,
            lowerMinOs: false,
            wildcardAppId: true
        )
    }
}
