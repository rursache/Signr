# CLAUDE.md

Rules and quick reference for Signr (`ro.randusoft.signr`), a native macOS IPA signing app targeting macOS 26+

## Build and run

```sh
./build.sh    # compiles Rust core → xcframework, runs xcodegen, builds the app, refreshes the Signr.app symlink
open Signr.app
```

After any Rust change, rerun `./build.sh` (or `rust/build-xcframework.sh` alone) to regenerate the xcframework and UniFFI bindings

Tests:

```sh
xcodebuild -scheme Signr -destination 'platform=macOS,arch=arm64' test
```

## Workflow

- Commit and push after each change
- Branch: `master`, remote: `https://github.com/rursache/Signr`

## Layout

- `app/` — Swift sources (App, Model, Views, Bridge)
- `rust/signr_core/` — thin async Rust facade exposed via UniFFI
- `rust/vendor/` — vendored PlumeImpactor crates (edited locally, no upstream sync expected)
- `Tests/` — FFI round-trip tests
- `rust/build/` and `Signr.xcodeproj` are gitignored and recreated by the build

## Key constraints

- **Non-sandboxed** — talking to `usbmuxd` is incompatible with the App Sandbox, so `ENABLE_APP_SANDBOX = NO`
- **Swift 5 language mode** — UniFFI 0.31 generated bindings are not Swift 6 strict-concurrency clean; `build-xcframework.sh` patches vtable pointer declarations with `nonisolated(unsafe)` as a workaround
- **Vendored crates** — do not run `cargo update` without reviewing changes and retesting the full FFI round-trip
- **Anisette has two tiers** (`plume_core/src/auth/anisette_data.rs`): native AOSKit (`native_anisette`) → opt-in remote anisette-v3 that must run Mac ADI (default `https://mac-ani.jkcoxson.com`). macOS 27 blocks the native tier outright (`com.apple.ak.anisette.xpc` refuses every process regardless of signing), so it lands on remote there; macOS 26 and earlier still use native and send exactly the headers they always did
- **Remote tier mirrors AltServer 1.8.2**: GSA and 2FA requests send the server's `/v3/client_info` client-info and user agent verbatim with `X-Xcode-Version 27.0 (27A5218g)`, `X-Apple-App-Info com.apple.gs.xcode.auth` and `Connection: close`, while developer services keep `User-Agent Xcode` and `11.2 (11B41)`; state lives in `anisette/servers/<host>/state.plist`, keyed by the client-info it was provisioned under, only `AnisetteData::new` may provision a new identity, and Android or Windows servers are refused before Apple is contacted
- **Client-info must say `com.apple.akd/1.0`**: Apple's GSA edge returns HTTP 503 for anything naming `com.apple.dt.Xcode`; native client-info is rewritten, remote servers naming Xcode are refused

## Coding style

- Never use em-dash characters anywhere (in code, comments, strings, docs, or commits); restructure the sentence instead
- Never end a sentence with a period in any written text
- Only add comments for tricky, non-obvious, or hacky code — not on every function, struct, or property
- Keep comments short
- `AppModel` is `@MainActor`; Rust calls run in a `Task { }` and update state back on the main actor
- Prefer `@Observable` and `@State` over `ObservableObject`/`@StateObject` for new model types
- Bridge types (`ProgressBridge`, `DeviceBridge`, `TwoFactorBridge`) are `@unchecked Sendable` — keep them as thin wrappers with no mutable state
