// The real unpack step of the sign pipeline: Package::new + get_package_bundle on the fixture
// IPA must produce a .app bundle with the expected structure.

use plume_utils::{Package, PlistInfoTrait};
use std::path::PathBuf;

fn fixture_ipa() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Tests/test_app.ipa"))
}

#[test]
fn unpacks_the_ipa_into_a_structured_app_bundle() {
    let pkg = Package::new(fixture_ipa()).expect("package should open");
    let bundle = pkg.get_package_bundle().expect("package should unpack");

    let app = bundle.bundle_dir();
    assert_eq!(
        app.extension().and_then(|e| e.to_str()),
        Some("app"),
        "unpacked bundle is a .app"
    );
    assert!(app.join("Info.plist").exists(), "Info.plist extracted");
    assert!(app.join("CloudPhotoManager").exists(), "main executable extracted");
    assert!(
        app.join("PlugIns").join("fileprovider.appex").exists(),
        "nested app extension extracted"
    );
    assert_eq!(
        bundle.get_bundle_identifier().as_deref(),
        Some("com.skyjos.cloudphoto"),
        "bundle id readable from the unpacked Info.plist"
    );

    pkg.remove_package_stage();
}
