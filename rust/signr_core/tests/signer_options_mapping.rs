// build_signer_options maps the FFI SignOptions record onto plume_utils::SignerOptions. Guards
// the wiring that every new toggle extends (and that the off path stays clean).

use plume_utils::SignerMode;
use signr_core::{SignOptions, build_signer_options};

#[test]
fn maps_every_feature_flag() {
    let mut o = SignOptions::default();
    o.remove_url_schemes = true;
    o.remove_ui_supported_devices = true;
    o.increased_memory_limit = true;
    o.enable_file_sharing = true;
    o.enable_ipad_fullscreen = true;
    o.enable_pro_motion = true;
    o.enable_game_mode = true;
    o.enable_liquid_glass = true;
    o.enable_ellekit = true;
    o.lower_min_os = true;

    let s = build_signer_options(&o);

    assert!(s.features.remove_url_schemes);
    assert!(s.features.remove_ui_supported_devices);
    assert!(s.features.support_increased_memory_limit);
    assert!(s.features.support_file_sharing);
    assert!(s.features.support_ipad_fullscreen);
    assert!(s.features.support_pro_motion);
    assert!(s.features.support_game_mode);
    assert!(s.features.support_liquid_glass);
    assert!(s.features.support_ellekit);
    assert!(s.features.support_minimum_os_version);
}

#[test]
fn defaults_leave_every_feature_off() {
    let s = build_signer_options(&SignOptions::default());

    assert!(!s.features.remove_url_schemes);
    assert!(!s.features.remove_ui_supported_devices);
    assert!(!s.features.support_increased_memory_limit);
    assert!(!s.features.support_file_sharing);
    assert!(matches!(s.mode, SignerMode::Pem), "signing mode is always Apple ID");
}

#[test]
fn maps_custom_fields_and_tweaks() {
    let mut o = SignOptions::default();
    o.custom_bundle_id = Some("com.example.x".into());
    o.custom_name = Some("Renamed".into());
    o.custom_version = Some("9.9".into());
    o.custom_icon_path = Some("/tmp/icon.png".into());
    o.tweaks = vec!["/tmp/a.dylib".into(), "/tmp/b.deb".into()];

    let s = build_signer_options(&o);

    assert_eq!(s.custom_identifier.as_deref(), Some("com.example.x"));
    assert_eq!(s.custom_name.as_deref(), Some("Renamed"));
    assert_eq!(s.custom_version.as_deref(), Some("9.9"));
    assert_eq!(s.custom_icon.as_deref(), Some(std::path::Path::new("/tmp/icon.png")));
    assert_eq!(s.tweaks.as_ref().map(|t| t.len()), Some(2));
}

#[test]
fn empty_tweaks_map_to_none() {
    assert!(build_signer_options(&SignOptions::default()).tweaks.is_none());
}
