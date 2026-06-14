// read_ipa_info parses the top-level app's Info.plist from a real IPA fixture.

use signr_core::read_ipa_info;

fn fixture_ipa() -> String {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../Tests/test_app.ipa").to_string()
}

#[test]
fn reads_metadata_from_the_fixture_ipa() {
    let info = read_ipa_info(fixture_ipa()).expect("fixture IPA should parse");

    assert_eq!(info.bundle_id.as_deref(), Some("com.skyjos.cloudphoto"));
    assert_eq!(info.name.as_deref(), Some("Photo Manager"));
    assert_eq!(info.version.as_deref(), Some("6.7.1"));
    assert_eq!(info.build.as_deref(), Some("6711"));
    assert_eq!(info.min_os.as_deref(), Some("15.0"));
}

#[test]
fn missing_ipa_path_is_an_error_not_a_panic() {
    assert!(read_ipa_info("/no/such/file.ipa".to_string()).is_err());
}
