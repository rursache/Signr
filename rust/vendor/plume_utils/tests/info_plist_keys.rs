// Bundle::set_info_plist_key / remove_info_plist_key round-trips on a synthetic .app.

use plume_utils::Bundle;
use std::fs;
use std::path::PathBuf;

fn temp_app(plist_xml: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("signr_plist_{}", uuid::Uuid::new_v4()));
    let app = root.join("Test.app");
    fs::create_dir_all(&app).unwrap();
    fs::write(app.join("Info.plist"), plist_xml).unwrap();
    app
}

fn read_dict(app: &PathBuf) -> plist::Dictionary {
    plist::Value::from_file(app.join("Info.plist"))
        .unwrap()
        .as_dictionary()
        .unwrap()
        .clone()
}

const BASE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.app</string>
    <key>CFBundleExecutable</key>
    <string>App</string>
    <key>CFBundleURLTypes</key>
    <array><dict><key>CFBundleURLSchemes</key><array><string>myscheme</string></array></dict></array>
</dict>
</plist>
"#;

#[test]
fn set_inserts_a_new_key_without_touching_others() {
    let app = temp_app(BASE);
    let bundle = Bundle::new(&app).unwrap();

    bundle.set_info_plist_key("UIFileSharingEnabled", true).unwrap();

    let dict = read_dict(&app);
    assert_eq!(
        dict.get("UIFileSharingEnabled").and_then(|v| v.as_boolean()),
        Some(true)
    );
    assert_eq!(
        dict.get("CFBundleIdentifier").and_then(|v| v.as_string()),
        Some("com.example.app")
    );
    fs::remove_dir_all(app.parent().unwrap()).ok();
}

#[test]
fn set_overwrites_an_existing_key() {
    let app = temp_app(BASE);
    let bundle = Bundle::new(&app).unwrap();

    bundle.set_info_plist_key("CFBundleIdentifier", "com.changed").unwrap();

    assert_eq!(
        read_dict(&app).get("CFBundleIdentifier").and_then(|v| v.as_string()),
        Some("com.changed")
    );
    fs::remove_dir_all(app.parent().unwrap()).ok();
}

#[test]
fn remove_strips_only_the_target_key() {
    let app = temp_app(BASE);
    let bundle = Bundle::new(&app).unwrap();
    assert!(read_dict(&app).contains_key("CFBundleURLTypes"));

    bundle.remove_info_plist_key("CFBundleURLTypes").unwrap();

    let dict = read_dict(&app);
    assert!(!dict.contains_key("CFBundleURLTypes"), "target key removed");
    assert!(dict.contains_key("CFBundleIdentifier"), "other keys retained");
    fs::remove_dir_all(app.parent().unwrap()).ok();
}

#[test]
fn remove_of_a_missing_key_is_a_noop() {
    let app = temp_app(BASE);
    let bundle = Bundle::new(&app).unwrap();

    bundle.remove_info_plist_key("DoesNotExist").unwrap();

    assert!(read_dict(&app).contains_key("CFBundleIdentifier"));
    fs::remove_dir_all(app.parent().unwrap()).ok();
}
