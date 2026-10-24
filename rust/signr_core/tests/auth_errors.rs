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
fn every_anisette_rejection_keeps_its_code() {
    for code in [-80045, -80046, -22421] {
        let e = Error::AuthSrpWithMessage(code, "rejected".into());
        match classify_core_error(&e) {
            Some(SignrError::AnisetteRejected { code: got, .. }) => assert_eq!(got, -code),
            other => panic!("{code} classified as {other:?}"),
        }
    }
}

#[test]
fn old_mac_identity_is_classified() {
    let e = Error::AuthSrpWithMessage(-23782, "A Mac with macOS version 10.13 or later".into());
    assert!(matches!(classify_core_error(&e), Some(SignrError::AccountNeedsNewerMac { .. })));
}

#[test]
fn non_mac_server_is_classified() {
    let e = Error::AnisetteProvider(plume_core::omnisette::AnisetteError::UnsupportedServerIdentity {
        client_info: "<MacBookPro13,2> <macOS;13.1;22C65> <x>".into(),
    });
    assert!(matches!(
        classify_core_error(&e),
        Some(SignrError::AnisetteServerUnsupported { .. })
    ));
}

#[test]
fn apple_outages_are_classified() {
    for status in [429, 503] {
        let e = Error::GsaHttp { url: "u".into(), status };
        assert!(matches!(
            classify_core_error(&e),
            Some(SignrError::AppleUnavailable { status: s }) if s == status
        ));
    }
    let e = Error::GsaHttp { url: "u".into(), status: 415 };
    assert!(classify_core_error(&e).is_none());
}

#[test]
fn expired_developer_session_is_classified() {
    let e = Error::DeveloperApi {
        url: "u".into(),
        result_code: 1100,
        http_code: Some(200),
        message: "Your session has expired".into(),
    };
    assert!(matches!(classify_core_error(&e), Some(SignrError::SessionExpired)));
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
