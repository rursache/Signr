// read_ipa_icon extracts the largest app icon and normalizes CgBI-encoded PNGs to a standard
// PNG (so the result must carry the PNG signature).

use signr_core::read_ipa_icon;

const PNG_MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

fn fixture_ipa() -> String {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../Tests/test_app.ipa").to_string()
}

#[test]
fn returns_a_standard_png_icon() {
    let bytes = read_ipa_icon(fixture_ipa()).expect("fixture IPA should have an icon");

    assert!(bytes.len() > PNG_MAGIC.len());
    assert_eq!(&bytes[..8], &PNG_MAGIC, "icon must be a normalized standard PNG");
}

#[test]
fn missing_ipa_path_returns_none() {
    assert!(read_ipa_icon("/no/such/file.ipa".to_string()).is_none());
}
