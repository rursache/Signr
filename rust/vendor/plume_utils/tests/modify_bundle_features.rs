// Signer::modify_bundle plist mutations, one assertion per feature flag. Covers the toggles
// wired into the app (remove URL schemes, remove UISupportedDevices, file sharing, iPad
// fullscreen, game mode, ProMotion, lower min OS) plus a regression check that an all-off
// options value leaves the Info.plist untouched.

use plume_utils::{Bundle, Signer, SignerMode, SignerOptions};
use std::fs;
use std::path::PathBuf;

const PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.app</string>
    <key>CFBundleExecutable</key>
    <string>App</string>
    <key>CFBundleURLTypes</key>
    <array><dict><key>CFBundleURLSchemes</key><array><string>myscheme</string></array></dict></array>
    <key>UISupportedDevices</key>
    <array><string>iPhone14,2</string></array>
</dict>
</plist>
"#;

fn temp_app() -> PathBuf {
    let root = std::env::temp_dir().join(format!("signr_modify_{}", uuid::Uuid::new_v4()));
    let app = root.join("Test.app");
    fs::create_dir_all(&app).unwrap();
    fs::write(app.join("Info.plist"), PLIST).unwrap();
    app
}

// plume_utils' tokio has no `macros` feature, so drive the async method on a manual runtime.
fn run_with(configure: impl FnOnce(&mut SignerOptions)) -> plist::Dictionary {
    let app = temp_app();
    let bundle = Bundle::new(&app).unwrap();

    let mut options = SignerOptions::default();
    options.mode = SignerMode::Pem;
    configure(&mut options);

    let mut signer = Signer::new(None, options);
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(signer.modify_bundle(&bundle, &None)).unwrap();

    let dict = plist::Value::from_file(app.join("Info.plist"))
        .unwrap()
        .as_dictionary()
        .unwrap()
        .clone();
    fs::remove_dir_all(app.parent().unwrap()).ok();
    dict
}

#[test]
fn remove_url_schemes_strips_cfbundleurltypes() {
    let d = run_with(|o| o.features.remove_url_schemes = true);
    assert!(!d.contains_key("CFBundleURLTypes"));
    assert!(d.contains_key("UISupportedDevices"), "unrelated keys untouched");
}

#[test]
fn remove_ui_supported_devices_strips_the_allowlist() {
    let d = run_with(|o| o.features.remove_ui_supported_devices = true);
    assert!(!d.contains_key("UISupportedDevices"));
    assert!(d.contains_key("CFBundleURLTypes"), "unrelated keys untouched");
}

#[test]
fn file_sharing_sets_both_keys() {
    let d = run_with(|o| o.features.support_file_sharing = true);
    assert_eq!(d.get("UIFileSharingEnabled").and_then(|v| v.as_boolean()), Some(true));
    assert_eq!(d.get("UISupportsDocumentBrowser").and_then(|v| v.as_boolean()), Some(true));
}

#[test]
fn ipad_fullscreen_sets_requires_full_screen() {
    let d = run_with(|o| o.features.support_ipad_fullscreen = true);
    assert_eq!(d.get("UIRequiresFullScreen").and_then(|v| v.as_boolean()), Some(true));
}

#[test]
fn game_mode_sets_supports_game_mode() {
    let d = run_with(|o| o.features.support_game_mode = true);
    assert_eq!(d.get("GCSupportsGameMode").and_then(|v| v.as_boolean()), Some(true));
}

#[test]
fn pro_motion_disables_minimum_frame_duration() {
    let d = run_with(|o| o.features.support_pro_motion = true);
    assert_eq!(
        d.get("CADisableMinimumFrameDurationOnPhone").and_then(|v| v.as_boolean()),
        Some(true)
    );
}

#[test]
fn lower_min_os_rewrites_minimum_os_version() {
    let d = run_with(|o| o.features.support_minimum_os_version = true);
    assert_eq!(d.get("MinimumOSVersion").and_then(|v| v.as_string()), Some("7.0"));
}

#[test]
fn applies_team_id_suffix_to_the_bundle_identifier() {
    // modify_bundle, when no custom id is set and a team id is supplied, derives
    // "<original>.<team_id>" and rewrites the bundle id (the free-account path).
    let app = temp_app();
    let bundle = Bundle::new(&app).unwrap();

    let mut options = SignerOptions::default();
    options.mode = SignerMode::Pem;
    let mut signer = Signer::new(None, options);

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(signer.modify_bundle(&bundle, &Some("TEAMID".to_string())))
        .unwrap();

    let dict = plist::Value::from_file(app.join("Info.plist"))
        .unwrap()
        .as_dictionary()
        .unwrap()
        .clone();
    assert_eq!(
        dict.get("CFBundleIdentifier").and_then(|v| v.as_string()),
        Some("com.example.app.TEAMID")
    );
    fs::remove_dir_all(app.parent().unwrap()).ok();
}

#[test]
fn all_features_off_leaves_the_plist_unchanged() {
    let d = run_with(|_| {});
    assert!(d.contains_key("CFBundleURLTypes"));
    assert!(d.contains_key("UISupportedDevices"));
    assert!(!d.contains_key("UIFileSharingEnabled"));
    assert!(!d.contains_key("GCSupportsGameMode"));
}
