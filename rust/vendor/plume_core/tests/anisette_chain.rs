//! End-to-end check of the anisette fallback chain (RS-263).
//!
//! Ignored by default: the remote tier talks to a third-party anisette server, so this is a
//! manual check rather than part of the normal suite. Run with:
//!   cargo test -p plume_core --features tweaks --test anisette_chain -- --ignored --nocapture

use plume_core::auth::anisette_data::AnisetteData;

const REQUIRED: [&str; 7] = [
    "X-Apple-I-MD",
    "X-Apple-I-MD-M",
    "X-Apple-I-MD-RINFO",
    "X-Apple-I-MD-LU",
    "X-Apple-I-SRL-NO",
    "X-Mme-Client-Info",
    "X-Mme-Device-Id",
];

#[tokio::test]
#[ignore]
async fn chain_yields_usable_headers_on_this_machine() {
    // SignrEngine does this at startup; the remote tier needs TLS.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let data = AnisetteData::new().await.expect("no anisette tier succeeded");
    println!("source: {:?}", data.source);

    let headers = data.generate_headers(false, true, true);
    for k in REQUIRED {
        assert!(
            headers.get(k).is_some_and(|v| !v.is_empty()),
            "missing header {k} (source {:?})",
            data.source
        );
    }

    let client_info = &headers["X-Mme-Client-Info"];
    assert!(client_info.contains("com.apple.akd/1.0"), "got {client_info}");
    assert!(!client_info.contains("dt.Xcode"), "got {client_info}");

    // macOS 27 must not be silently served by the dead native tier.
    if cfg!(target_os = "macos") {
        println!("client-info: {client_info}");
    }
}
