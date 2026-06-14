// The main_binary_only pipeline step: strip_non_main_bundles must remove PlugIns/Extensions/Watch
// from a real unpacked IPA and scrub the matching SC_Info manifest entries (so installd does not
// fail with PackageInspectionFailed).

use plume_utils::Package;
use signr_core::strip_non_main_bundles;
use std::path::PathBuf;

fn fixture_ipa() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Tests/test_app.ipa"))
}

#[test]
fn removes_plugins_and_scrubs_the_manifest() {
    let pkg = Package::new(fixture_ipa()).unwrap();
    let bundle = pkg.get_package_bundle().unwrap();
    let app = bundle.bundle_dir().clone();

    assert!(app.join("PlugIns").exists(), "fixture must have PlugIns to strip");

    let removed = strip_non_main_bundles(&bundle).expect("strip should succeed");

    assert!(removed.contains(&"PlugIns".to_string()), "PlugIns reported removed");
    assert!(!app.join("PlugIns").exists(), "PlugIns directory gone");

    // If the App Store manifest is present, it must no longer reference the removed dirs.
    let manifest = app.join("SC_Info").join("Manifest.plist");
    if manifest.exists() {
        let value = plist::Value::from_file(&manifest).unwrap();
        if let Some(paths) = value
            .as_dictionary()
            .and_then(|d| d.get("SinfReplicationPaths"))
            .and_then(|v| v.as_array())
        {
            assert!(
                paths
                    .iter()
                    .filter_map(|v| v.as_string())
                    .all(|s| !s.starts_with("PlugIns/")),
                "manifest must not reference the removed PlugIns"
            );
        }
    }

    pkg.remove_package_stage();
}

#[test]
fn strip_is_a_noop_when_there_is_nothing_to_remove() {
    // A fresh unpack with the removable dirs already gone (we strip twice).
    let pkg = Package::new(fixture_ipa()).unwrap();
    let bundle = pkg.get_package_bundle().unwrap();
    strip_non_main_bundles(&bundle).unwrap();

    let removed_again = strip_non_main_bundles(&bundle).unwrap();
    assert!(removed_again.is_empty(), "second strip removes nothing");

    pkg.remove_package_stage();
}
