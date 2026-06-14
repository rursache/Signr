// Bundle::set_matching_identifier rewrites the main id and the WatchKit / app-extension ids
// that reference it, via substring replacement.

use plume_utils::Bundle;
use std::fs;
use std::path::PathBuf;

const PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.app</string>
    <key>WKCompanionAppBundleIdentifier</key>
    <string>com.example.app.watch</string>
    <key>NSExtension</key>
    <dict>
        <key>NSExtensionAttributes</key>
        <dict>
            <key>WKAppBundleIdentifier</key>
            <string>com.example.app.watchkitapp</string>
        </dict>
    </dict>
</dict>
</plist>
"#;

fn temp_app() -> PathBuf {
    let root = std::env::temp_dir().join(format!("signr_matchid_{}", uuid::Uuid::new_v4()));
    let app = root.join("Test.app");
    fs::create_dir_all(&app).unwrap();
    fs::write(app.join("Info.plist"), PLIST).unwrap();
    app
}

#[test]
fn rewrites_main_companion_and_extension_ids() {
    let app = temp_app();
    let bundle = Bundle::new(&app).unwrap();

    bundle
        .set_matching_identifier("com.example.app", "com.example.app.TEAMID")
        .unwrap();

    let v = plist::Value::from_file(app.join("Info.plist")).unwrap();
    let d = v.as_dictionary().unwrap();

    assert_eq!(
        d.get("CFBundleIdentifier").and_then(|x| x.as_string()),
        Some("com.example.app.TEAMID")
    );
    assert_eq!(
        d.get("WKCompanionAppBundleIdentifier").and_then(|x| x.as_string()),
        Some("com.example.app.TEAMID.watch")
    );
    let wk = d
        .get("NSExtension")
        .and_then(|x| x.as_dictionary())
        .and_then(|x| x.get("NSExtensionAttributes"))
        .and_then(|x| x.as_dictionary())
        .and_then(|x| x.get("WKAppBundleIdentifier"))
        .and_then(|x| x.as_string());
    assert_eq!(wk, Some("com.example.app.TEAMID.watchkitapp"));

    fs::remove_dir_all(app.parent().unwrap()).ok();
}
