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

## Coding style

- Never use em-dash characters anywhere (in code, comments, strings, docs, or commits); restructure the sentence instead
- Never end a sentence with a period in any written text
- Only add comments for tricky, non-obvious, or hacky code — not on every function, struct, or property
- Keep comments short
- `AppModel` is `@MainActor`; Rust calls run in a `Task { }` and update state back on the main actor
- Prefer `@Observable` and `@State` over `ObservableObject`/`@StateObject` for new model types
- Bridge types (`ProgressBridge`, `DeviceBridge`, `TwoFactorBridge`) are `@unchecked Sendable` — keep them as thin wrappers with no mutable state
