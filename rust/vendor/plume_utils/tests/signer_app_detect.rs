// SignerApp detection from bundle id, with name as a fallback.

use plume_utils::SignerApp;

#[test]
fn detects_known_apps_by_bundle_id() {
    assert_eq!(
        SignerApp::from_bundle_identifier(Some("com.rileytestut.AltStore")),
        SignerApp::AltStore
    );
    assert_eq!(
        SignerApp::from_bundle_identifier(Some("com.SideStore.SideStore")),
        SignerApp::SideStore
    );
    assert_eq!(
        SignerApp::from_bundle_identifier(Some("com.kdt.livecontainer")),
        SignerApp::LiveContainer
    );
}

#[test]
fn unknown_or_missing_bundle_id_is_default() {
    assert_eq!(
        SignerApp::from_bundle_identifier(Some("com.some.random.app")),
        SignerApp::Default
    );
    assert_eq!(SignerApp::from_bundle_identifier(None::<&str>), SignerApp::Default);
}

#[test]
fn falls_back_to_name_when_bundle_id_is_unknown() {
    assert_eq!(
        SignerApp::from_bundle_identifier_or_name(Some("com.unknown.x"), Some("My SideStore Build")),
        SignerApp::SideStore
    );
    assert_eq!(
        SignerApp::from_bundle_identifier_or_name(None::<&str>, Some("Feather")),
        SignerApp::Feather
    );
    assert_eq!(
        SignerApp::from_bundle_identifier_or_name(None::<&str>, None::<&str>),
        SignerApp::Default
    );
}

#[test]
fn bundle_id_wins_over_name() {
    assert_eq!(
        SignerApp::from_bundle_identifier_or_name(
            Some("com.rileytestut.AltStore"),
            Some("Feather")
        ),
        SignerApp::AltStore
    );
}
