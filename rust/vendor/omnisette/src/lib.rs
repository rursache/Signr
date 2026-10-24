//! Remote anisette-v3 client, the emulated Android ADI provider is gone because Apple
//! rejects Android CoreADI data since October 2026 (-80045, -80046)

use std::io;
use thiserror::Error;

pub mod anisette_headers_provider;

#[cfg(feature = "remote-anisette-v3")]
pub mod remote_anisette_v3;

#[derive(Debug, Error)]
pub enum AnisetteError {
    #[error("Invalid argument {0}")]
    InvalidArgument(String),
    #[error("Anisette not provisioned!")]
    AnisetteNotProvisioned,
    #[error("This anisette identity has to be provisioned again before it can be used")]
    NeedsProvisioning,
    #[error("The anisette identity changed in the middle of a sign-in")]
    IdentityChanged,
    #[error("The anisette server reports an identity Apple rejects ({client_info})")]
    UnsupportedServerIdentity { client_info: String },
    #[error("The anisette server reported an unusable identity: {0}")]
    InvalidClientInfo(String),
    #[error("The anisette server failed to generate headers: {0}")]
    GetHeaders(String),
    #[error("Anisette provisioning failed: {0}")]
    Provisioning(String),
    #[error("Anisette provisioning timed out")]
    ProvisioningTimeout,
    #[error("Anisette resync is not possible: {0}")]
    ResyncUnavailable(String),
    #[error("Plist serialization error {0}")]
    PlistError(#[from] plist::Error),
    #[error("Request Error {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[cfg(feature = "remote-anisette-v3")]
    #[error("Provisioning socket error {0}")]
    WsError(#[from] tokio_tungstenite::tungstenite::error::Error),
    #[cfg(feature = "remote-anisette-v3")]
    #[error("JSON error {0}")]
    SerdeError(#[from] serde_json::Error),
    #[error("IO error {0}")]
    IOError(#[from] io::Error),
}

/// Mac ADI server, the same host AltStore lists as ani.jkcoxson.com
pub const DEFAULT_ANISETTE_URL_V3: &str = "https://mac-ani.jkcoxson.com";
