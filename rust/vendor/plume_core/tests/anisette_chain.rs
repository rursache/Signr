//! End-to-end check of the anisette chain (RS-263)
//!
//! Ignored by default: on a Mac without native anisette it provisions a new identity with
//! gsa.apple.com through the default server and replaces the one stored in Signr's anisette
//! folder, it never logs in, run it with:
//!   cargo test -p plume_core --features tweaks --test anisette_chain -- --ignored --nocapture

use plume_core::auth::anisette_data::{
    AnisetteData, AnisetteSettings, AnisetteSource, set_anisette_settings,
};

const REQUIRED: [&str; 6] = [
    "X-Apple-I-MD",
    "X-Apple-I-MD-M",
    "X-Apple-I-MD-RINFO",
    "X-Apple-I-MD-LU",
    "X-Mme-Client-Info",
    "X-Mme-Device-Id",
];

#[tokio::test]
#[ignore]
async fn chain_yields_usable_headers_on_this_machine() {
    // SignrEngine does this at startup; the remote tier needs TLS.
    let _ = rustls::crypto::ring::default_provider().install_default();
    set_anisette_settings(AnisetteSettings { allow_fallback: true, server_url: None });

    let data = AnisetteData::new().await.expect("no anisette tier succeeded");
    println!("source: {:?}", data.source);

    let headers = data.developer_headers().expect("unusable headers");
    for k in REQUIRED {
        assert!(
            headers.get(k).is_some_and(|v| !v.is_empty()),
            "missing header {k} (source {:?})",
            data.source
        );
    }
    assert!(!data.user_agent.is_empty());

    let client_info = headers["X-Mme-Client-Info"].to_str().unwrap();
    println!("client-info: {client_info}");
    println!("user agent: {}", data.user_agent);
    assert!(client_info.contains("com.apple.akd/1.0"), "got {client_info}");
    if data.source == AnisetteSource::RemoteV3 {
        assert!(!client_info.contains("<Android;") && !client_info.contains("13.1;22C65"));
        assert!(headers.get("X-Apple-I-SRL-NO").is_none());
    }

    let refreshed = data.refresh().await.expect("refresh failed");
    assert_eq!(
        refreshed.base_headers.get("X-Mme-Device-Id"),
        data.base_headers.get("X-Mme-Device-Id")
    );
}
