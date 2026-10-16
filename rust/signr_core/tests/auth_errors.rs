use plume_core::Error;
use signr_core::{SignrError, classify_core_error, normalize_server_url};

#[test]
fn account_lock_is_classified() {
    let e = Error::AuthSrpWithMessage(-20209, "This Apple Account has been locked".into());
    assert!(matches!(classify_core_error(&e), Some(SignrError::AccountLocked { .. })));
}

#[test]
fn anisette_rejection_is_classified() {
    let e = Error::AuthSrpWithMessage(-80045, "rejected".into());
    assert!(matches!(classify_core_error(&e), Some(SignrError::AnisetteRejected { .. })));
}

#[test]
fn positive_codes_match_too() {
    let e = Error::AuthSrpWithMessage(20209, "locked".into());
    assert!(matches!(classify_core_error(&e), Some(SignrError::AccountLocked { .. })));
}

#[test]
fn disabled_fallback_is_classified() {
    assert!(matches!(
        classify_core_error(&Error::AnisetteFallbackDisabled),
        Some(SignrError::AnisetteFallbackDisabled)
    ));
}

#[test]
fn other_auth_errors_pass_through() {
    let e = Error::AuthSrpWithMessage(-22406, "Enter the correct password".into());
    assert!(classify_core_error(&e).is_none());
    assert!(classify_core_error(&Error::Parse).is_none());
}

#[test]
fn server_url_is_normalized() {
    assert_eq!(normalize_server_url(None), None);
    assert_eq!(normalize_server_url(Some("  ".into())), None);
    assert_eq!(
        normalize_server_url(Some(" https://ani.example.com/ ".into())),
        Some("https://ani.example.com".into())
    );
    assert_eq!(normalize_server_url(Some("ani.example.com".into())), None);
    assert_eq!(normalize_server_url(Some("https://".into())), None);
    assert_eq!(normalize_server_url(Some("ftp://x".into())), None);
}
