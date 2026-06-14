import Foundation
import Darwin
import CryptoKit

/// At-rest encryption for the app-written data files (history, account cache), matching the
/// Rust side: the key is SHA256(host UUID + bundle id + salt), so the blob is machine-bound
/// and useless if copied off this Mac. AES-256-GCM via CryptoKit.
enum DataCrypto {
    private static let magic = Data("SGNRENC1".utf8)

    private static let key: SymmetricKey = {
        var uuid = [UInt8](repeating: 0, count: 16)
        var wait = timespec(tv_sec: 5, tv_nsec: 0)
        _ = gethostuuid(&uuid, &wait)
        var hasher = SHA256()
        hasher.update(data: Data(uuid))
        hasher.update(data: Data("ro.randusoft.signr".utf8))
        hasher.update(data: Data("signr-data-v1".utf8))
        return SymmetricKey(data: Data(hasher.finalize()))
    }()

    static func encrypt(_ data: Data) -> Data {
        guard let box = try? AES.GCM.seal(data, using: key), let combined = box.combined else {
            return data
        }
        return magic + combined
    }

    /// Returns nil when the data is not our blob (e.g. a legacy plaintext file), so callers
    /// can fall back to reading it directly and re-save it encrypted.
    static func decrypt(_ data: Data) -> Data? {
        guard data.count > magic.count, data.prefix(magic.count) == magic,
              let box = try? AES.GCM.SealedBox(combined: data.dropFirst(magic.count)),
              let plain = try? AES.GCM.open(box, using: key) else { return nil }
        return plain
    }
}
