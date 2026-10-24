use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

use omnisette::AnisetteError;
use omnisette::remote_anisette_v3::{APP_INFO, RemoteAnisetteProviderV3, XCODE_VERSION};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use crate::Error;

/// Which tier of the fallback chain produced a set of headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnisetteSource {
    /// This Mac's own ADI, via AOSKit talking to akd.
    Native,
    /// A remote anisette-v3 server running Mac ADI
    RemoteV3,
}

/// How many times to ask the remote provider before giving up
const ANISETTE_ATTEMPTS: u32 = 3;

/// Pause between those attempts. A single bad reply from ani.sidestore.app
/// used to abort the sign (RS-276)
const ANISETTE_RETRY_DELAY: Duration = Duration::from_secs(1);

/// What native logins have always sent, kept as is so macOS 26 and earlier behave as before
const NATIVE_USER_AGENT: &str = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0";
const DEVELOPER_XCODE_VERSION: &str = "11.2 (11B41)";

/// Where the remote provisioning state lives
fn anisette_config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home)
        .join("Library/Application Support/Signr")
        .join("anisette")
}

/// User controls for the remote tier, falling back is opt-in because Apple has been locking
/// accounts (-20209) that log in with public anisette servers
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnisetteSettings {
    pub allow_fallback: bool,
    /// anisette-v3 server to use instead of the default one
    pub server_url: Option<String>,
}

static SETTINGS: RwLock<AnisetteSettings> = RwLock::new(AnisetteSettings {
    allow_fallback: false,
    server_url: None,
});

static PROVISIONING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub fn set_anisette_settings(settings: AnisetteSettings) {
    *SETTINGS.write().unwrap_or_else(|e| e.into_inner()) = settings;
}

pub fn anisette_settings() -> AnisetteSettings {
    SETTINGS.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// True when this Mac hands out its own anisette (macOS 26 and earlier)
pub fn native_anisette_available() -> bool {
    native_anisette::base_headers().is_ok()
}

/// Every server gets its own subdirectory named after the URL, a provisioned identity only
/// works against the server that minted it
fn server_state_path(base: &Path, server_url: &str) -> PathBuf {
    let trimmed = server_url.trim_end_matches('/');
    let name: String = trimmed
        .split_once("://")
        .map_or(trimmed, |(_, rest)| rest)
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect();
    // "." or ".." would point outside servers/
    let name = if name.trim_matches('.').is_empty() { "_".to_string() } else { name };
    base.join("servers").join(name)
}

/// The old default server's identity sat in the base directory and came from Android CoreADI,
/// which Apple rejects, so it's never used again
fn remove_legacy_state(base: &Path) {
    let legacy = base.join("state.plist");
    if legacy.exists() {
        if let Err(e) = std::fs::remove_file(&legacy) {
            log::warn!("could not remove legacy anisette state ({e})");
        }
    }
}

/// The server and state directory a remote identity came from, refreshes and resyncs go back
/// to exactly this, even if the user picks another server in the middle of a sign-in
#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteOrigin {
    server_url: String,
    state_path: PathBuf,
}

impl RemoteOrigin {
    fn from_settings() -> Self {
        let server_url = anisette_settings()
            .server_url
            .unwrap_or_else(|| omnisette::DEFAULT_ANISETTE_URL_V3.to_string());
        let base = anisette_config_path();
        remove_legacy_state(&base);
        RemoteOrigin {
            state_path: server_state_path(&base, &server_url),
            server_url,
        }
    }

    fn provider(&self) -> RemoteAnisetteProviderV3 {
        RemoteAnisetteProviderV3::new(self.server_url.clone(), self.state_path.clone())
    }
}

fn header_map<'a>(
    pairs: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<HeaderMap, Error> {
    let mut headers = HeaderMap::new();
    for (k, v) in pairs {
        let name = HeaderName::from_bytes(k.as_bytes())
            .map_err(|_| Error::InvalidHeader(k.to_string()))?;
        let value = HeaderValue::from_str(v).map_err(|_| Error::InvalidHeader(k.to_string()))?;
        headers.insert(name, value);
    }
    Ok(headers)
}

#[derive(Debug, Clone)]
pub struct AnisetteData {
    pub base_headers: HashMap<String, String>,
    pub generated_at: SystemTime,
    pub source: AnisetteSource,
    /// Sent with every GrandSlam request, it has to match the device behind the anisette
    pub user_agent: String,
    origin: Option<RemoteOrigin>,
}

impl AnisetteData {
    pub async fn new() -> Result<Self, Error> {
        // Tier 1: this Mac's native ADI. Preferred wherever it works, so nothing changes on
        // macOS 26 and earlier. macOS 27 refuses the com.apple.ak.anisette.xpc connection and
        // hands back empty headers, which is what drops us onto the remote tier
        match Self::native().await {
            Ok(data) => return Ok(data),
            Err(e) => log::warn!("native anisette unavailable ({e})"),
        }

        if !anisette_settings().allow_fallback {
            return Err(Error::AnisetteFallbackDisabled);
        }

        Self::remote(RemoteOrigin::from_settings(), true).await
    }

    async fn native() -> Result<Self, Error> {
        match tokio::task::spawn_blocking(native_anisette::base_headers).await {
            Ok(Ok(base_headers)) => Ok(Self::from_native(base_headers)),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(Error::AnisetteUnavailable("native anisette panicked".into())),
        }
    }

    /// Network hiccups against the anisette server are retried, but only on the path that
    /// never talks to Apple, and a new identity is provisioned at most once and only when
    /// `allow_provisioning` is set, the way AltServer re-provisions when the server's identity
    /// changes or it forgets ours (-45061)
    async fn remote(origin: RemoteOrigin, allow_provisioning: bool) -> Result<Self, Error> {
        let fetched = retry_anisette(ANISETTE_ATTEMPTS, ANISETTE_RETRY_DELAY, || {
            let origin = origin.clone();
            async move { Ok(origin.provider().headers(false).await?) }
        })
        .await;
        let base_headers = match fetched {
            Ok(headers) => headers,
            Err(Error::AnisetteProvider(AnisetteError::NeedsProvisioning)) if allow_provisioning => {
                // A sign-in and a session restore starting together must not mint two identities
                let _guard = PROVISIONING.lock().await;
                match origin.provider().headers(false).await {
                    Err(AnisetteError::NeedsProvisioning) => {
                        log::info!("provisioning a new anisette identity with {}", origin.server_url);
                        origin.provider().headers(true).await?
                    }
                    other => other?,
                }
            }
            Err(e) => return Err(e),
        };
        log::info!("anisette headers sourced from {}", origin.server_url);
        Self::from_remote(base_headers, origin)
    }

    fn from_native(base_headers: HashMap<String, String>) -> Self {
        AnisetteData {
            base_headers,
            generated_at: SystemTime::now(),
            source: AnisetteSource::Native,
            user_agent: NATIVE_USER_AGENT.to_string(),
            origin: None,
        }
    }

    fn from_remote(
        mut base_headers: HashMap<String, String>,
        origin: RemoteOrigin,
    ) -> Result<Self, Error> {
        let user_agent = base_headers.remove("User-Agent").ok_or_else(|| {
            AnisetteError::InvalidClientInfo("the server sent no user agent".into())
        })?;
        Ok(AnisetteData {
            base_headers,
            generated_at: SystemTime::now(),
            source: AnisetteSource::RemoteV3,
            user_agent,
            origin: Some(origin),
        })
    }

    pub fn needs_refresh(&self) -> bool {
        self.generated_at
            .elapsed()
            .map_or(true, |elapsed| elapsed.as_secs() > 60)
    }

    pub fn is_valid(&self) -> bool {
        self.generated_at
            .elapsed()
            .is_ok_and(|elapsed| elapsed.as_secs() < 90)
    }

    fn identity(&self) -> (Option<&String>, Option<&String>) {
        (
            self.base_headers.get("X-Mme-Device-Id"),
            self.base_headers.get("X-Mme-Client-Info"),
        )
    }

    fn same_identity(self, previous: &Self) -> Result<Self, Error> {
        if self.identity() != previous.identity() {
            return Err(AnisetteError::IdentityChanged.into());
        }
        Ok(self)
    }

    /// New one-time password from the same source and identity, never a new identity
    pub async fn refresh(&self) -> Result<Self, Error> {
        let fresh = match &self.origin {
            None => Self::native().await?,
            Some(origin) => Self::remote(origin.clone(), false).await?,
        };
        fresh.same_identity(self)
    }

    /// Answer Apple's hsc 434 with the X-Apple-I-MD-DATA it sent
    pub async fn resync(&self, sim: &str) -> Result<Self, Error> {
        let Some(origin) = &self.origin else {
            return Err(Error::AnisetteResync(
                "this Mac's own anisette can't be resynced".into(),
            ));
        };
        let headers = origin.provider().resync(sim).await?;
        Self::from_remote(headers, origin.clone())?.same_identity(self)
    }

    fn client_info(&self) -> Result<&str, Error> {
        self.base_headers
            .get("X-Mme-Client-Info")
            .map(String::as_str)
            .ok_or(Error::DeveloperSessionRequestFailed)
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.base_headers.get(name).map(String::as_str)
    }

    /// Native keeps the exact headers Signr has always sent, the remote tier mirrors AltSign
    /// with the server's client-info and user agent verbatim and Xcode 27's version
    pub fn gsa_headers(&self) -> Result<HeaderMap, Error> {
        match self.source {
            AnisetteSource::Native => {
                let client_info = rewrite_client_info(self.client_info()?).to_lowercase();
                header_map([
                    ("Content-Type", "text/x-xml-plist"),
                    ("Accept", "*/*"),
                    ("User-Agent", NATIVE_USER_AGENT),
                    ("X-MMe-Client-Info", client_info.as_str()),
                ])
            }
            AnisetteSource::RemoteV3 => header_map([
                ("Content-Type", "text/x-xml-plist"),
                ("Accept", "text/x-xml-plist"),
                ("X-MMe-Client-Info", self.client_info()?),
                ("User-Agent", self.user_agent.as_str()),
                ("X-Xcode-Version", XCODE_VERSION),
                ("X-Apple-App-Info", APP_INFO),
                ("Connection", "close"),
            ]),
        }
    }

    pub fn cpd(&self) -> plist::Dictionary {
        let mut cpd = plist::Dictionary::new();
        let loc = match self.source {
            AnisetteSource::Native => {
                for (k, v) in &self.base_headers {
                    if k != "X-Mme-Client-Info" {
                        cpd.insert(k.clone(), plist::Value::String(v.clone()));
                    }
                }
                "en_GB"
            }
            AnisetteSource::RemoteV3 => {
                for k in ["X-Apple-I-MD", "X-Apple-I-MD-M", "X-Mme-Device-Id"] {
                    if let Some(v) = self.header(k) {
                        cpd.insert(k.to_string(), plist::Value::String(v.to_string()));
                    }
                }
                "en_US"
            }
        };
        for (k, v) in [
            ("bootstrap", "true"),
            ("icscrec", "true"),
            ("loc", loc),
            ("pbe", "false"),
            ("prkgen", "true"),
            ("svct", "iCloud"),
        ] {
            cpd.insert(k.to_string(), plist::Value::String(v.to_string()));
        }
        cpd
    }

    fn anisette_pairs(&self) -> Result<Vec<(&str, &str)>, Error> {
        let client_info = match self.source {
            AnisetteSource::Native => None,
            AnisetteSource::RemoteV3 => Some(self.client_info()?),
        };
        Ok(self
            .base_headers
            .iter()
            .filter(|(k, _)| k.as_str() != "X-Mme-Client-Info")
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .chain(client_info.map(|c| ("X-Mme-Client-Info", c)))
            .collect())
    }

    /// gsa.apple.com/auth calls (trusted device push, SMS, GsService2/validate)
    pub fn two_factor_headers(&self, sms: bool) -> Result<HeaderMap, Error> {
        let content_type = if sms { "application/json" } else { "text/x-xml-plist" };
        let mut pairs = self.anisette_pairs()?;
        let native_client_info;
        let (xcode_version, user_agent) = match self.source {
            AnisetteSource::Native => {
                native_client_info = rewrite_client_info(self.client_info()?);
                pairs.push(("X-Mme-Client-Info", native_client_info.as_str()));
                (DEVELOPER_XCODE_VERSION, "Xcode")
            }
            AnisetteSource::RemoteV3 => {
                pairs.push(("Connection", "close"));
                (XCODE_VERSION, self.user_agent.as_str())
            }
        };
        // Same order native has always sent
        pairs.extend([
            ("X-Apple-App-Info", APP_INFO),
            ("X-Xcode-Version", xcode_version),
            ("Content-Type", content_type),
            ("Accept", content_type),
            ("User-Agent", user_agent),
            ("Accept-Language", "en-us"),
        ]);
        header_map(pairs)
    }

    /// Developer services keep User-Agent Xcode and Xcode 11.2, as AltSign does
    pub fn developer_headers(&self) -> Result<HeaderMap, Error> {
        let mut pairs = self.anisette_pairs()?;
        let native_client_info;
        if self.source == AnisetteSource::Native {
            native_client_info = rewrite_client_info(self.client_info()?);
            pairs.push(("X-Mme-Client-Info", native_client_info.as_str()));
        } else {
            pairs.push(("X-Apple-I-Locale", "en_US"));
        }
        pairs.extend([
            ("X-Apple-App-Info", APP_INFO),
            ("X-Xcode-Version", DEVELOPER_XCODE_VERSION),
        ]);
        header_map(pairs)
    }
}

/// Retry `op` up to `attempts` times with `delay` between failures, except for errors that
/// a retry can't fix, the last error is returned as-is so a real outage still shows up
async fn retry_anisette<T, F, Fut>(attempts: u32, delay: Duration, mut op: F) -> Result<T, Error>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, Error>>,
{
    let mut attempt = 1u32;
    loop {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) if attempt >= attempts || !is_retryable(&err) => return Err(err),
            Err(err) => {
                log::warn!("anisette attempt {attempt}/{attempts} failed ({err}), retrying");
                tokio::time::sleep(delay).await;
                attempt += 1;
            }
        }
    }
}

fn is_retryable(err: &Error) -> bool {
    !matches!(
        err,
        Error::AnisetteFallbackDisabled
            | Error::AnisetteProvider(
                AnisetteError::NeedsProvisioning
                    | AnisetteError::IdentityChanged
                    | AnisetteError::UnsupportedServerIdentity { .. }
                    | AnisetteError::InvalidClientInfo(_)
                    | AnisetteError::ResyncUnavailable(_)
            )
    )
}

/// The agent identity Apple's GSA edge accepts. Anything naming com.apple.dt.Xcode has been
/// answered with HTTP 503 since Sept 2026, it's only applied to this Mac's own client-info
/// since a remote server's identity is sent verbatim and servers naming Xcode are refused
const AGENT: &str = "com.apple.AuthKit/1 (com.apple.akd/1.0)";

/// Swap the agent out of a `<hw> <os> <agent>` client-info triple, leaving the device and OS
/// parts as the provider reported them.
fn rewrite_client_info(value: &str) -> String {
    match value.split('<').nth(3).and_then(|s| s.split('>').next()) {
        Some(agent) => value.replace(agent, AGENT),
        // Not the shape we expect, so append the agent rather than silently leaving a
        // client-info Apple will reject.
        None => format!("{value} <{AGENT}>"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NATIVE_INFO: &str =
        "<iMac21,1> <macOS;27.0;26A428> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>";
    const MAC_INFO: &str =
        "<MacBookPro13,3> <Mac OS X;10.12.6;16G29> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
    const MAC_UA: &str = "akd/1.0 CFNetwork/811.5.4 Darwin/16.7.0";

    fn native_with(client_info: &str) -> AnisetteData {
        let mut base = HashMap::new();
        for (k, v) in [
            ("X-Apple-I-MD", "otp"),
            ("X-Apple-I-MD-M", "mid"),
            ("X-Apple-I-MD-RINFO", "17106176"),
            ("X-Apple-I-MD-LU", "lu"),
            ("X-Apple-I-SRL-NO", "C02SERIAL"),
            ("X-Mme-Client-Info", client_info),
            ("X-Mme-Device-Id", "UDID"),
        ] {
            base.insert(k.to_string(), v.to_string());
        }
        AnisetteData::from_native(base)
    }

    fn remote() -> AnisetteData {
        let mut base = HashMap::new();
        for (k, v) in [
            ("X-Apple-I-MD", "otp"),
            ("X-Apple-I-MD-M", "mid"),
            ("X-Apple-I-MD-RINFO", "17106176"),
            ("X-Apple-I-MD-LU", "abc123"),
            ("X-Apple-I-Client-Time", "2026-10-24T08:00:00Z"),
            ("X-Apple-I-TimeZone", "UTC"),
            ("X-Apple-Locale", "en_US"),
            ("X-Mme-Client-Info", MAC_INFO),
            ("X-Mme-Device-Id", "7f3c2b1a-0000-4000-8000-000000000000"),
            ("User-Agent", MAC_UA),
        ] {
            base.insert(k.to_string(), v.to_string());
        }
        let origin = RemoteOrigin {
            server_url: "https://mac-ani.example.com".into(),
            state_path: PathBuf::from("/x"),
        };
        AnisetteData::from_remote(base, origin).unwrap()
    }

    fn get<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
        headers.get(name).unwrap().to_str().unwrap()
    }

    // RS-263: a client-info naming com.apple.dt.Xcode gets HTTP 503 from Apple.
    #[test]
    fn rewrites_xcode_agent_to_akd() {
        let out = rewrite_client_info(NATIVE_INFO);
        assert_eq!(
            out,
            "<iMac21,1> <macOS;27.0;26A428> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
        );
        assert!(!out.contains("dt.Xcode"));
    }

    #[test]
    fn rewrite_keeps_hardware_and_os_parts() {
        let out = rewrite_client_info(
            "<MacBookPro13,2> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",
        );
        assert!(out.starts_with("<MacBookPro13,2> <macOS;13.1;22C65>"));
        assert!(out.ends_with(&format!("<{AGENT}>")));
    }

    #[test]
    fn rewrite_is_idempotent() {
        let already = "<iMac21,1> <macOS;27.0;26A428> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
        assert_eq!(rewrite_client_info(already), already);
    }

    #[test]
    fn rewrite_appends_agent_when_shape_is_unexpected() {
        let out = rewrite_client_info("<iMac21,1> <macOS;27.0;26A428>");
        assert!(out.ends_with(&format!("<{AGENT}>")));
    }

    #[test]
    fn native_gsa_headers_are_unchanged() {
        let headers = native_with(NATIVE_INFO).gsa_headers().unwrap();
        assert_eq!(headers.len(), 4);
        assert_eq!(get(&headers, "Accept"), "*/*");
        assert_eq!(get(&headers, "User-Agent"), NATIVE_USER_AGENT);
        assert_eq!(
            get(&headers, "X-MMe-Client-Info"),
            "<imac21,1> <macos;27.0;26a428> <com.apple.authkit/1 (com.apple.akd/1.0)>"
        );
    }

    #[test]
    fn native_cpd_is_unchanged() {
        let cpd = native_with(NATIVE_INFO).cpd();
        assert_eq!(cpd.len(), 12);
        assert_eq!(cpd.get("loc").unwrap().as_string(), Some("en_GB"));
        assert_eq!(cpd.get("X-Apple-I-SRL-NO").unwrap().as_string(), Some("C02SERIAL"));
        assert!(cpd.get("X-Mme-Client-Info").is_none());
    }

    #[test]
    fn native_two_factor_and_developer_headers_are_unchanged() {
        let data = native_with(NATIVE_INFO);
        for headers in [data.two_factor_headers(false).unwrap(), data.developer_headers().unwrap()] {
            assert_eq!(get(&headers, "X-Xcode-Version"), "11.2 (11B41)");
            assert_eq!(get(&headers, "X-Apple-App-Info"), APP_INFO);
            assert_eq!(get(&headers, "X-Apple-I-SRL-NO"), "C02SERIAL");
            assert_eq!(
                get(&headers, "X-Mme-Client-Info"),
                "<iMac21,1> <macOS;27.0;26A428> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
            );
            assert!(headers.get("Connection").is_none());
        }
        assert_eq!(get(&data.two_factor_headers(false).unwrap(), "User-Agent"), "Xcode");
        assert!(data.developer_headers().unwrap().get("User-Agent").is_none());
    }

    #[test]
    fn native_two_factor_header_order_is_unchanged() {
        let headers = native_with(NATIVE_INFO).two_factor_headers(false).unwrap();
        let names: Vec<_> = headers.keys().map(|k| k.as_str()).collect();
        assert_eq!(
            names[names.len() - 4..],
            ["content-type", "accept", "user-agent", "accept-language"]
        );
    }

    #[test]
    fn remote_gsa_headers_send_the_server_identity_verbatim() {
        let headers = remote().gsa_headers().unwrap();
        assert_eq!(get(&headers, "X-MMe-Client-Info"), MAC_INFO);
        assert_eq!(get(&headers, "User-Agent"), MAC_UA);
        assert_eq!(get(&headers, "Accept"), "text/x-xml-plist");
        assert_eq!(get(&headers, "X-Xcode-Version"), "27.0 (27A5218g)");
        assert_eq!(get(&headers, "X-Apple-App-Info"), "com.apple.gs.xcode.auth");
        assert_eq!(get(&headers, "Connection"), "close");
    }

    #[test]
    fn remote_cpd_matches_altsign() {
        let cpd = remote().cpd();
        let mut keys: Vec<_> = cpd.keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "X-Apple-I-MD", "X-Apple-I-MD-M", "X-Mme-Device-Id", "bootstrap", "icscrec", "loc",
                "pbe", "prkgen", "svct"
            ]
        );
        assert_eq!(cpd.get("loc").unwrap().as_string(), Some("en_US"));
    }

    #[test]
    fn remote_two_factor_headers_use_the_server_identity() {
        let data = remote();
        let headers = data.two_factor_headers(false).unwrap();
        assert_eq!(get(&headers, "User-Agent"), MAC_UA);
        assert_eq!(get(&headers, "X-Mme-Client-Info"), MAC_INFO);
        assert_eq!(get(&headers, "X-Xcode-Version"), "27.0 (27A5218g)");
        assert_eq!(get(&headers, "Content-Type"), "text/x-xml-plist");
        assert_eq!(get(&headers, "Connection"), "close");
        assert_eq!(get(&headers, "X-Apple-I-MD-LU"), "abc123");
        let sms = data.two_factor_headers(true).unwrap();
        assert_eq!(get(&sms, "Content-Type"), "application/json");
    }

    #[test]
    fn remote_developer_headers_keep_xcode_and_no_serial() {
        let headers = remote().developer_headers().unwrap();
        assert_eq!(get(&headers, "X-Xcode-Version"), "11.2 (11B41)");
        assert_eq!(get(&headers, "X-Mme-Client-Info"), MAC_INFO);
        assert_eq!(get(&headers, "X-Apple-I-Locale"), "en_US");
        assert!(headers.get("X-Apple-I-SRL-NO").is_none());
        assert!(headers.get("User-Agent").is_none());
    }

    #[test]
    fn remote_requires_a_user_agent() {
        let origin = RemoteOrigin { server_url: "https://x".into(), state_path: PathBuf::new() };
        let mut base = HashMap::new();
        base.insert("X-Mme-Client-Info".to_string(), MAC_INFO.to_string());
        assert!(AnisetteData::from_remote(base, origin).is_err());
    }

    #[test]
    fn header_values_that_would_break_a_request_are_errors() {
        let mut data = remote();
        data.user_agent = "akd\r\nX-Injected: 1".into();
        assert!(matches!(data.gsa_headers(), Err(Error::InvalidHeader(_))));
    }

    #[test]
    fn identity_changes_are_detected() {
        let a = remote();
        let mut b = remote();
        assert!(b.clone().same_identity(&a).is_ok());
        b.base_headers.insert("X-Mme-Device-Id".into(), "other".into());
        assert!(matches!(
            b.same_identity(&a),
            Err(Error::AnisetteProvider(AnisetteError::IdentityChanged))
        ));
    }

    #[test]
    fn source_is_recorded() {
        assert_eq!(native_with(NATIVE_INFO).source, AnisetteSource::Native);
        assert_eq!(remote().source, AnisetteSource::RemoteV3);
    }

    #[test]
    fn every_server_gets_its_own_state_dir() {
        let base = PathBuf::from("/x/anisette");
        assert_eq!(
            server_state_path(&base, omnisette::DEFAULT_ANISETTE_URL_V3),
            base.join("servers/mac-ani.jkcoxson.com")
        );
        assert_eq!(
            server_state_path(&base, "https://mac-ani.example.com/"),
            base.join("servers/mac-ani.example.com")
        );
        assert_eq!(
            server_state_path(&base, "http://10.0.0.2:6969"),
            base.join("servers/10.0.0.2_6969")
        );
        assert_eq!(server_state_path(&base, "https://.."), base.join("servers/_"));
        assert_ne!(
            server_state_path(&base, "https://a.example/?u=http://x"),
            server_state_path(&base, "https://b.example/?u=http://x")
        );
    }

    #[test]
    fn legacy_state_is_removed() {
        let dir = std::env::temp_dir().join(format!("signr-legacy-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("servers")).unwrap();
        std::fs::write(dir.join("state.plist"), b"x").unwrap();
        remove_legacy_state(&dir);
        assert!(!dir.join("state.plist").exists());
        assert!(dir.join("servers").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn config_path_is_under_app_support() {
        let p = anisette_config_path();
        assert!(p.ends_with("Signr/anisette"), "unexpected path {p:?}");
    }

    // RS-276: a decode failure from the server must be retried, and the
    // sign only stops once the last attempt fails with that same error
    #[tokio::test]
    async fn retries_until_anisette_succeeds() {
        let calls = std::sync::atomic::AtomicU32::new(0);
        let got = retry_anisette(3, Duration::ZERO, || {
            let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move { if n < 2 { Err(Error::Parse) } else { Ok(n) } }
        })
        .await
        .unwrap();
        assert_eq!(got, 2);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn stops_after_the_last_anisette_failure() {
        let calls = std::sync::atomic::AtomicU32::new(0);
        let err = retry_anisette(3, Duration::ZERO, || {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async { Err::<(), _>(Error::Parse) }
        })
        .await
        .unwrap_err();
        assert!(matches!(err, Error::Parse));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn does_not_retry_after_success() {
        let calls = std::sync::atomic::AtomicU32::new(0);
        let got = retry_anisette(3, Duration::ZERO, || {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async { Ok::<_, Error>(1) }
        })
        .await
        .unwrap();
        assert_eq!(got, 1);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn identity_problems_are_not_retried() {
        for make in [
            || Error::from(AnisetteError::NeedsProvisioning),
            || Error::from(AnisetteError::UnsupportedServerIdentity { client_info: "x".into() }),
            || Error::from(AnisetteError::IdentityChanged),
        ] {
            let calls = std::sync::atomic::AtomicU32::new(0);
            let _ = retry_anisette(3, Duration::ZERO, || {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move { Err::<(), _>(make()) }
            })
            .await;
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        }
    }
}
