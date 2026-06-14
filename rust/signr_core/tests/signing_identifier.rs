// The App ID / bundle-id decision that drives registration and signing: free-team suffixing,
// custom-id override, and the paid-only wildcard rule.

use signr_core::{resolve_signing_identifier, use_wildcard_app_id};

#[test]
fn free_team_appends_the_team_id_suffix() {
    assert_eq!(
        resolve_signing_identifier(None, Some("com.example.app"), "TEAMID", true),
        Some("com.example.app.TEAMID".to_string())
    );
}

#[test]
fn paid_team_keeps_the_identifier_verbatim() {
    assert_eq!(
        resolve_signing_identifier(None, Some("com.example.app"), "TEAMID", false),
        Some("com.example.app".to_string())
    );
}

#[test]
fn custom_id_overrides_original_and_still_suffixes_on_free() {
    assert_eq!(
        resolve_signing_identifier(Some("com.custom.id"), Some("com.example.app"), "TEAMID", true),
        Some("com.custom.id.TEAMID".to_string())
    );
}

#[test]
fn empty_custom_id_falls_back_to_the_original() {
    assert_eq!(
        resolve_signing_identifier(Some(""), Some("com.example.app"), "TEAMID", false),
        Some("com.example.app".to_string())
    );
}

#[test]
fn no_identifier_at_all_resolves_to_none() {
    assert_eq!(resolve_signing_identifier(None, None, "TEAMID", true), None);
}

#[test]
fn wildcard_is_paid_team_only() {
    assert!(use_wildcard_app_id(true, false), "paid + requested -> wildcard");
    assert!(!use_wildcard_app_id(true, true), "free + requested -> never wildcard");
    assert!(!use_wildcard_app_id(false, false), "paid + not requested -> no wildcard");
}
