import AppKit
import UniformTypeIdentifiers

/// Resolves a user-picked icon into a raster PNG (plus a preview) for the signer to bake into the
/// IPA's loose icon files. A PNG passes straight through. An Icon Composer ".icon" package is a
/// design-time source iOS never reads at runtime, so we flatten it to a static light-appearance
/// render: first via Icon Composer's `icontool` when it's installed, otherwise by compositing the
/// package's `icon.json` layers ourselves. The dynamic Liquid Glass / dark variants can't be
/// injected into a pre-built IPA, so the light render is the most we can carry.
enum IconImport {
    enum Failure: LocalizedError {
        case unreadable
        case iconRenderFailed
        var errorDescription: String? {
            switch self {
            case .unreadable: "Could not read the selected image"
            case .iconRenderFailed: "Could not render the .icon file — export a 1024×1024 PNG instead"
            }
        }
    }

    /// Synchronous and potentially slow (spawns `icontool` / composites layers); call off the main
    /// actor via `Task.detached`.
    static func resolve(_ url: URL) throws -> (png: URL, preview: NSImage) {
        if url.pathExtension.lowercased() == "icon" {
            let png = try flattenDotIcon(url)
            guard let preview = NSImage(contentsOf: png) else { throw Failure.iconRenderFailed }
            return (png, preview)
        }
        guard let preview = NSImage(contentsOf: url) else { throw Failure.unreadable }
        return (url, preview)
    }

    // MARK: - .icon flattening

    private static func flattenDotIcon(_ iconURL: URL) throws -> URL {
        let out = FileManager.default.temporaryDirectory
            .appendingPathComponent("signr-icon-\(UUID().uuidString).png")
        if let tool = iconToolURL(), runIconTool(tool, icon: iconURL, out: out) {
            return out
        }
        if compositeDotIcon(iconURL, to: out, size: 1024) {
            return out
        }
        throw Failure.iconRenderFailed
    }

    /// Locate Icon Composer's private export CLI (ships inside Xcode and the standalone app).
    private static func iconToolURL() -> URL? {
        let candidates = [
            "/Applications/Icon Composer.app/Contents/Executables/icontool",
            "/Applications/Icon Composer.app/Contents/Executables/ictool",
            "/Applications/Xcode.app/Contents/Applications/Icon Composer.app/Contents/Executables/icontool",
            "/Applications/Xcode.app/Contents/Applications/Icon Composer.app/Contents/Executables/ictool",
        ]
        return candidates.map { URL(fileURLWithPath: $0) }
            .first { FileManager.default.isExecutableFile(atPath: $0.path) }
    }

    /// `ictool input.icon --export-image --output-file <png> --platform iOS --rendition Default
    /// --width 1024 --height 1024 --scale 1` — the documented invocation (verified against
    /// `ictool --help` in Xcode 26's Icon Composer).
    private static func runIconTool(_ tool: URL, icon: URL, out: URL) -> Bool {
        try? FileManager.default.removeItem(at: out)
        let proc = Process()
        proc.executableURL = tool
        proc.arguments = [
            icon.path, "--export-image", "--output-file", out.path,
            "--platform", "iOS", "--rendition", "Default",
            "--width", "1024", "--height", "1024", "--scale", "1",
        ]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        do {
            try proc.run()
            proc.waitUntilExit()
            return proc.terminationStatus == 0 && isValidPNG(out)
        } catch {
            return false
        }
    }

    private static func isValidPNG(_ url: URL) -> Bool {
        guard let data = try? Data(contentsOf: url, options: .mappedIfSafe), data.count > 8 else { return false }
        return data.prefix(8).elementsEqual([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
    }

    // MARK: - Manual fallback: composite icon.json layers (flat, light appearance)

    private static func compositeDotIcon(_ iconURL: URL, to out: URL, size: Int) -> Bool {
        let assets = iconURL.appendingPathComponent("Assets")
        guard let data = try? Data(contentsOf: iconURL.appendingPathComponent("icon.json")),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let ctx = CGContext(
                data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0,
                space: CGColorSpace(name: CGColorSpace.sRGB)!,
                bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)
        else { return false }

        let dim = CGFloat(size)
        // Background fill (light appearance); white when absent or a gradient we don't parse.
        let bg = solidColor((root["fill"] as? [String: Any])?["solid"] as? String)
            ?? CGColor(red: 1, green: 1, blue: 1, alpha: 1)
        ctx.setFillColor(bg)
        ctx.fill(CGRect(x: 0, y: 0, width: dim, height: dim))

        // Layers, back to front. Icon Composer authors layers full-canvas, so default scale 1 +
        // no translation stacks them correctly; scale/translation refine the placement.
        for group in (root["groups"] as? [[String: Any]]) ?? [] {
            for layer in (group["layers"] as? [[String: Any]]) ?? [] {
                guard let name = layer["image-name"] as? String,
                      let img = NSImage(contentsOf: assets.appendingPathComponent(name)),
                      let cg = img.cgImage(forProposedRect: nil, context: nil, hints: nil)
                else { continue }
                let pos = layer["position"] as? [String: Any]
                let scale = CGFloat(pos?["scale"] as? Double ?? 1)
                let t = pos?["translation-in-points"] as? [Double] ?? [0, 0]
                let w = dim * scale, h = dim * scale
                let x = (dim - w) / 2 + CGFloat(t.first ?? 0)
                // icon.json y is top-down, CoreGraphics is bottom-up.
                let y = (dim - h) / 2 - CGFloat(t.count > 1 ? t[1] : 0)
                ctx.draw(cg, in: CGRect(x: x, y: y, width: w, height: h))
            }
        }

        guard let outImage = ctx.makeImage(),
              let png = NSBitmapImageRep(cgImage: outImage).representation(using: .png, properties: [:])
        else { return false }
        return (try? png.write(to: out)) != nil
    }

    /// Parse an Icon Composer color like "display-p3:0.07,0.09,0.16,1.0" or "srgb:r,g,b,a".
    private static func solidColor(_ s: String?) -> CGColor? {
        guard let s, let colon = s.firstIndex(of: ":") else { return nil }
        let comps = s[s.index(after: colon)...].split(separator: ",").compactMap { Double($0) }
        guard comps.count >= 3 else { return nil }
        let cgSpace = s[..<colon].lowercased().contains("p3")
            ? CGColorSpace(name: CGColorSpace.displayP3)!
            : CGColorSpace(name: CGColorSpace.sRGB)!
        let a = comps.count >= 4 ? comps[3] : 1
        return CGColor(colorSpace: cgSpace, components: [comps[0], comps[1], comps[2], a].map { CGFloat($0) })
    }
}
