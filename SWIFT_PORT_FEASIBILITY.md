# Porting Signr's Rust core to native Swift

Feasibility analysis, captured 2026-06-13. This documents whether the remaining Rust
(`signr_core` + the vendored PlumeImpactor crates) could be rewritten in native Swift to drop
Rust altogether, what each piece would take, and the recommendation

## Verdict

A full "drop Rust entirely, pure Swift" port is **not achievable as stated**. **Two** subsystems
block it, and both are load-bearing:

1. **Code signing** has no pure-Swift implementation and one cannot reasonably be written. Every
   tool in this space compiles a C++ engine (ldid or zsign) in-process; Signr uses `apple-codesign`
   (Rust), the most complete of the lot
2. **Device comms** has no viable native path for iOS 17+. Apple changed the device transport in
   iOS 17 (CDC-NCM + RemoteXPC/RSD tunnel), and only the `idevice` Rust crate (with its `rsd`
   feature) implements both protocol generations. The test iPad runs iOS 26 and depends on it

So "no Rust" actually means "swap Rust for C++ and an iOS-17+ regression", which is a net loss

What is achievable is a **hybrid**: native Swift for the genuinely portable pieces, while the
signer and the device stack stay Rust. Whether that is worth it is the real question, and the
answer is mostly no, with one carve-out worth doing on its own merit (Keychain for accounts)

## Current architecture and size

```
Swift UI ─ UniFFI ─ signr_core ─┬─ plume_store     (accounts, encrypted at rest)
                                 ├─ plume_core ─ native_anisette (AOSKit)
                                 ├─ plume_utils ─ decompress     (.deb)
                                 └─ idevice        (USB device stack)
```

| Crate | LOC | Responsibility | Heavy external deps |
|---|---|---|---|
| `signr_core` | 1252 | UniFFI facade the app calls | uniffi, tokio |
| `native_anisette` | 147 | AOSKit anisette (already native) | objc2 |
| `plume_core` | 3514 | GSA/SRP auth, dev portal API, certs, Mach-O | srp, rsa, x509, rcgen, p12-keystore, apple-codesign, goblin, reqwest |
| `plume_utils` | 2595 | packaging, signing orchestration, device install, tweaks | idevice, zip, rayon, memmap2, image |
| `plume_store` | 416 | account persistence (AES-256-GCM) | aes-gcm, sha2, serde |
| `decompress` | 1436 | `.deb`/ar/tar extraction | ar, tar, flate2, xz2, zstd |

The real weight is not our ~9.4k LOC, it is the external crates that reimplement Apple machinery:
`apple-codesign` (Mach-O signing), `idevice` (device protocols), and the crypto stack. Those are
what a port must replace

## Component-by-component assessment

| Component | Native Swift path | Effort | Risk |
|---|---|---|---|
| Anisette | AOSKit, already a thin Swift-callable shim | Trivial | None |
| Account storage | Keychain + Codable | Trivial | None |
| CgBI PNG fix | ImageIO decodes CgBI natively, the module disappears | Trivial | None |
| ZIP / IPA pack-unpack | ZIPFoundation (libcompression) | Low | Low |
| `.deb` extraction | ~50-line `ar` parser + `Process` to `/usr/bin/tar` | Low-Med | Low |
| Dev portal API | URLSession + PropertyListEncoder/Decoder | Low | Low |
| RSA keygen + CSR | `SecKeyCreateRandomKey` + `apple/swift-certificates` | Low-Med | Low |
| Mach-O read/merge entitlements | MachOKit (read) + PropertyListSerialization (merge) | Low | Low |
| Dylib injection (`LC_LOAD_DYLIB`) | `paradiseduo/inject` SPM, or raw `Data` splice | Low-Med | Low |
| GSA SRP-6a auth | `swift-srp` + `swift-crypto`; s2k pre-hash is delicate | Medium | Med |
| PKCS#12 assembly | temp-keychain round-trip (no in-memory `SecIdentity` API) | Medium | Med |
| **Device comms** (usbmux/lockdown/AFC/instproxy + iOS 17+ RSD tunnel) | **no viable native path for iOS 17+** | **Hard** | **High** |
| **Code signing** | **none pure-Swift exists** | **Hard** | **High** |

## The signing wall (the decisive constraint)

`apple-codesign` (indygreg's `apple-platform-rs`, vendored by PlumeImpactor) is the most complete
open implementation: SHA-256-primary CodeDirectory, DER entitlements, `CS_EXECSEG_MAIN_BINARY` on
extensions, nested-bundle + Watch-app handling. That last flag is the reason Signr's injected
`.appex` tweaks launch on iOS 26 (AMFI kills extensions that carry entitlements without it)

No pure-Swift signer exists. Confirmed across the ecosystem:

- **AltStore / SideStore** compile a vendored fork of **ldid** (C++) in-process via
  `ALTSigner.mm` calling `ldid::Sign()`. ldid alone does CodeDirectory + CMS but not
  CodeResources, bundle traversal, or provisioning; AltSign wraps it with that orchestration in
  ObjC++
- **Feather** wraps **zsign** (C++) as a Swift Package
- **zsign** reimplements everything in C++, but its source hardcodes only the G1/G3 WWDR
  intermediate CAs (`X509_issuer_name_hash` lookup), so it fails CMS generation for certs issued
  under WWDR G4-G8, which is essentially every Apple Developer cert issued today, and it defaults
  to SHA-1-primary CodeDirectory (rejected on modern iOS without the `-2` flag). Real regressions
- **system `/usr/bin/codesign`** can sign iOS ARM64 bundles, but: it needs the Xcode toolchain
  present (`codesign_allocate`), `--deep` silently signs only the main binary of an iOS-style
  bundle (so you must sign inside-out per binary), it needs `--generate-entitlement-der` for
  CodeDirectory v=20500 on iOS 15+, and the key must be imported into a keychain with the
  `security set-key-partition-list` dance (no public API for the partition list). Requiring Xcode
  defeats the "standalone signer" premise

Net: signing keeps a non-Swift component no matter what. The current Rust `apple-codesign` is the
best version of that component, and replacing it trades correctness for "language purity"

## Device comms: a second hard constraint (the iOS 17+ transport)

This was initially assessed as a clean native win via Apple's private `MobileDevice.framework`.
Deeper research overturned that. The device layer is a **second** reason to keep Rust, not a
simplification target

The decisive fact: **iOS 17 changed the device transport**. Pre-iOS-17 used usbmux (TCP over USB);
iOS 17+ added CDC-NCM (a virtual Ethernet / IPv6 link) plus a RemoteXPC / RSD tunnel (SRP key
exchange + QUIC + XPC framing) for developer services. Classic lockdown services like
`installation_proxy` and AFC still work over usbmux for app install, but the framework-level tools
that drive the old path are no longer reliable on modern iOS:

- `MobileDevice.framework` (`AMDeviceSecureTransferPath` + `AMDeviceSecureInstallApplication`):
  ios-deploy, the canonical consumer, now states it is "designed to work on un-jailbroken devices
  running iOS versions prior to iOS17". Xcode 15 moved iOS 17+ to the fully private
  `CoreDevice.framework` (no public API, only `xcrun devicectl`). The one dedicated Swift wrapper,
  `lfroms/mobile-device-kit`, was archived November 2024 with the note that private-API churn is
  not worth debugging. Verdict: works for iOS < 17, a dead-end risk for iOS 17+
- **libimobiledevice** (via `SideStore/iMobileDevice.swift` or `SwiftyMobileDevice`): more
  complete and actively maintained, statically linkable via SPM (no .dylib to bundle), but the
  full RemoteXPC/RSD tunnel is not implemented as of early 2026, so iOS 17+ reliability is
  uncertain. Plus LGPL relink obligations
- **Pure-Swift reimplementation**: does not exist. The only pure-Swift usbmux libraries
  (SteveTrewick/USBmuxd, DarkLightning) do TCP tunneling only. A from-scratch stack is
  ~3,000-6,000 LOC for the pre-iOS-17 protocols alone, and iOS 17+ would need a QUIC stack that
  `Network.framework` does not expose for local device connections. Not viable
- **`idevice` (Rust, current)**: the only production-proven implementation that covers **both**
  protocol generations. Signr pins it with the `usbmuxd` and `rsd` features precisely so it
  handles iOS 17+ via the RSD tunnel. Used in production by StikDebug, CrossCode, Protokolle. This
  is what makes installs work on a modern iPad (the test device runs iOS 26)

So the device layer is the second crown jewel. Replacing `idevice` with `MobileDevice.framework`
or libimobiledevice would trade a working iOS-26 install path for an iOS-17+ dead-end or an
uncertain shim. It stays Rust

## Auth + crypto port notes

This layer is a routine Swift port, proven by **AltSign** doing the exact same thing in ObjC:

- **SRP-6a / GSA**: `swift-srp` (RFC 5054, SHA-256, N2048) + `swift-crypto`. The one careful piece
  is Apple's `s2k` / `s2k_fo` password pre-hash (PBKDF2-HMAC-SHA256 with server salt + iterations
  before SRP), plus AES-CBC (login) and AES-GCM (tokens) session decryption. AltSign's
  `ALTAppleAPI+Authentication.m` is a line-for-line blueprint. ~300-500 LOC, medium effort, fails
  opaquely if a byte order is wrong
- **Dev portal**: URLSession + plist. AltSign's `ALTAppleAPI.m` implements every endpoint
  (fetchTeams, addCertificate, app IDs, app groups, fetchProvisioningProfile, registerDevice).
  Nothing exotic
- **RSA keygen + CSR**: `SecKeyCreateRandomKey(RSA 2048)`, then `apple/swift-certificates` for the
  PKCS#10 CSR (it wraps `SecKeyCreateSignature(.rsaSignatureMessagePKCS1v15SHA256)`). Note
  `SecKeyCopyExternalRepresentation` returns PKCS#1, not SPKI; on macOS use
  `SecItemExport(kSecFormatOpenSSL)` to get SubjectPublicKeyInfo DER
- **PKCS#12 assembly**: the awkward bit. There is no public API to build a `SecIdentity` from an
  in-memory cert+key, so you either add both to a temporary keychain and `SecItemExport(kSecFormatPKCS12)`,
  or keep a tiny crypto helper. Watch for the Sequoia `SecPKCS12Import` regressions (-25293 on
  empty password, OpenSSL-3 SHA-256 MAC rejected, use `-legacy`)
- **Mach-O**: MachOKit reads load commands and entitlements; `paradiseduo/inject` (SPM) adds
  `LC_LOAD_DYLIB`. Entitlement merge is PropertyListSerialization + string work

## Candidate end-state architectures

- **A. Status quo** — Swift UI + Rust core via UniFFI. Ships today, correct on iOS 26
- **B. Hybrid** — native Swift for auth/portal/certs/macho/zip/storage, but keep **both**
  `apple-codesign` and `idevice` as Rust modules behind a thinner FFI. Shrinks Rust by dropping
  `plume_store`, `decompress`, and most of `plume_core`, but the two heaviest crates and their
  UniFFI surface stay. Modest simplification for substantial effort
- **C. Full Swift + bundled zsign/ldid C++ + libimobiledevice C** — zero Rust, but inherits
  zsign's modern-cert bugs and libimobiledevice's uncertain iOS 17+ support. "No Rust" but "yes
  C++", with two correctness downgrades on things that currently work
- **D. Pure Swift, no native signer and no device stack** — impossible

## Recommendation

Do **not** undertake the full port (B or C). It is weeks-to-months of re-deriving working code,
and the SRP s2k, PKCS#12, and signing-orchestration rewrites are exactly where subtle,
hard-to-debug regressions live. The payoff is "less Rust", not a capability gain, and the three
load-bearing pieces (the working GSA auth, the best-in-class signer, and the only iOS-17+-capable
device stack) have no better native form

One piece is worth doing on its own merit, low risk, real payoff:

1. **Accounts to Keychain** — drops `plume_store` and its AES/SHA/serde stack, and is arguably
   more secure than the current host-UUID-derived file encryption. Smallest, safest first step

The signer (`apple-codesign`) and the device stack (`idevice`, with its `rsd` feature for iOS 17+)
both stay Rust, because that is where Rust is pulling weight that Swift cannot match. An earlier
draft of this doc suggested `MobileDevice.framework` for device install; that was wrong, it is an
iOS-17+ dead-end and would break installs on modern devices

## Key libraries and APIs referenced

- Signing: `apple-codesign` / `indygreg/apple-platform-rs` (keep), zsign (`zhlynn/zsign`, buggy
  WWDR table), ldid (`ProcursusTeam/ldid`), `jveko/zsign-rs`
- Device: `jkcoxson/idevice` (keep, the only iOS-17+-capable stack via `rsd`/RemoteXPC).
  `MobileDevice.framework` (`AMDevice*`) and libimobiledevice wrappers (`SwiftyMobileDevice`,
  `SideStore/iMobileDevice.swift`) are iOS<17 / uncertain-on-17+ and not recommended
- Auth/crypto: `adam-fowler/swift-srp`, `apple/swift-crypto`, `apple/swift-certificates`,
  `apple/swift-asn1`, `rileytestut/AltSign` (ObjC reference)
- Mach-O: `p-x9/MachOKit`, `paradiseduo/inject`
- Archives: `weichsel/ZIPFoundation`, system `libarchive` / `/usr/bin/tar`
