use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

use omnisette::{AnisetteConfiguration, AnisetteHeaders, AnisetteHeadersProviderType};

use crate::Error;

/// Which tier of the fallback chain produced a set of headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnisetteSource {
    /// This Mac's own ADI, via AOSKit talking to akd.
    Native,
    /// Emulated ADI, running Apple's algorithm out of the Android GSA library.
    EmulatedAdi,
    /// A remote anisette-v3 server.
    RemoteV3,
}

/// How many times to ask the emulated or remote provider before giving up
const ANISETTE_ATTEMPTS: u32 = 3;

/// Pause between those attempts. A single bad reply from ani.sidestore.app
/// used to abort the sign (RS-276)
const ANISETTE_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Where the emulated-ADI library and the remote provisioning blob live.
fn anisette_config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home)
        .join("Library/Application Support/Signr")
        .join("anisette")
}

/// User controls for the tiers below native. Apple has been locking accounts (-20209) that
/// log in with public anisette servers, so falling back is opt-in, emulated ADI included
/// since it runs the same Android CoreADI the rejected servers use
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

/// Remote state for the default server stays in the base directory so existing installs keep
/// their provisioning, custom servers get a subdirectory named after the URL
fn remote_state_path(base: &std::path::Path, server_url: Option<&str>) -> PathBuf {
    match server_url {
        None => base.to_path_buf(),
        Some(url) => {
            let trimmed = url.trim_end_matches('/');
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
    }
}

#[derive(Debug, Clone)]
pub struct AnisetteData {
    pub base_headers: HashMap<String, String>,
    pub generated_at: SystemTime,
    pub source: AnisetteSource,
}

impl AnisetteData {
    pub async fn new() -> Result<Self, Error> {
        // Tier 1: this Mac's native ADI. Preferred wherever it works, so nothing changes on
        // macOS 26 and earlier. macOS 27 refuses the com.apple.ak.anisette.xpc connection and
        // hands back empty headers, which is what drops us onto the tiers below.
        match tokio::task::spawn_blocking(native_anisette::base_headers).await {
            Ok(Ok(base_headers)) => {
                return Ok(Self::from_headers(base_headers, AnisetteSource::Native));
            }
            Ok(Err(e)) => log::warn!("native anisette unavailable ({e})"),
            Err(_) => log::warn!("native anisette panicked"),
        }

        if !anisette_settings().allow_fallback {
            return Err(Error::AnisetteFallbackDisabled);
        }

        // Tiers 2 and 3. Each attempt builds a fresh provider. Native stays a
        // single shot: its failure on macOS 27 is deterministic
        retry_anisette(
            ANISETTE_ATTEMPTS,
            ANISETTE_RETRY_DELAY,
            Self::fetch_fallback,
        )
        .await
    }

    /// Emulated ADI when `libstoreservicescore.so` is provisioned, otherwise remote v3
    async fn fetch_fallback() -> Result<Self, Error> {
        let settings = anisette_settings();
        let base = anisette_config_path();
        let mut config = AnisetteConfiguration::new()
            .set_remote_configuration_path(remote_state_path(&base, settings.server_url.as_deref()))
            .set_configuration_path(base)
            .set_macos_serial(native_anisette::machine_serial().unwrap_or_else(|| "0".to_string()));
        if let Some(url) = settings.server_url {
            config = config.set_anisette_url_v3(url);
        }

        let mut res = AnisetteHeaders::get_anisette_headers_provider(config)?;
        let source = match &res.provider_type {
            AnisetteHeadersProviderType::Local => AnisetteSource::EmulatedAdi,
            AnisetteHeadersProviderType::Remote => AnisetteSource::RemoteV3,
        };
        let base_headers = res.provider.get_authentication_headers().await?;
        log::info!("anisette headers sourced from {source:?}");

        Ok(Self::from_headers(base_headers, source))
    }

    fn from_headers(base_headers: HashMap<String, String>, source: AnisetteSource) -> Self {
        AnisetteData {
            base_headers,
            generated_at: SystemTime::now(),
            source,
        }
    }

    pub fn needs_refresh(&self) -> bool {
        let elapsed = self.generated_at.elapsed().unwrap();
        elapsed.as_secs() > 60
    }

    pub fn is_valid(&self) -> bool {
        let elapsed = self.generated_at.elapsed().unwrap();
        elapsed.as_secs() < 90
    }

    pub async fn refresh(&self) -> Result<Self, crate::Error> {
        Self::new().await
    }

    pub fn generate_headers(
        &self,
        cpd: bool,
        client_info: bool,
        app_info: bool,
    ) -> HashMap<String, String> {
        // Stale headers get a clean error back from Apple, a panic here kills the whole sign
        if !self.is_valid() {
            log::warn!("anisette data is stale and could not be refreshed");
        }

        let mut headers = self.base_headers.clone();
        let old_client_info = headers.remove("X-Mme-Client-Info");

        if client_info {
            let client_info = match old_client_info {
                Some(v) => rewrite_client_info(&v),
                None => {
                    return headers;
                }
            };
            headers.insert("X-Mme-Client-Info".to_owned(), client_info);
        }

        if app_info {
            headers.insert(
                "X-Apple-App-Info".to_owned(),
                "com.apple.gs.xcode.auth".to_owned(),
            );
            headers.insert("X-Xcode-Version".to_owned(), "11.2 (11B41)".to_owned());
        }

        if cpd {
            headers.insert("bootstrap".to_owned(), "true".to_owned());
            headers.insert("icscrec".to_owned(), "true".to_owned());
            headers.insert("loc".to_owned(), "en_GB".to_owned());
            headers.insert("pbe".to_owned(), "false".to_owned());
            headers.insert("prkgen".to_owned(), "true".to_owned());
            headers.insert("svct".to_owned(), "iCloud".to_owned());
        }

        headers
    }

    pub fn to_plist(&self, cpd: bool, client_info: bool, app_info: bool) -> plist::Dictionary {
        let mut plist = plist::Dictionary::new();
        for (key, value) in self.generate_headers(cpd, client_info, app_info).iter() {
            plist.insert(key.to_owned(), plist::Value::String(value.to_owned()));
        }

        plist
    }

    pub fn get_header(&self, header: &str) -> Result<String, Error> {
        let headers = self
            .generate_headers(true, true, true)
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
            .collect::<HashMap<String, String>>();

        match headers.get(&header.to_lowercase()) {
            Some(v) => Ok(v.to_string()),
            None => Err(Error::DeveloperSessionRequestFailed),
        }
    }
}

/// Call `op` up to `attempts` times. Sleep `delay` between failures. The last
/// error is returned as-is, so a real outage still shows up after the retries
async fn retry_anisette<T, F, Fut>(attempts: u32, delay: Duration, mut op: F) -> Result<T, Error>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, Error>>,
{
    let mut attempt = 1u32;
    loop {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) if attempt >= attempts => return Err(err),
            Err(err) => {
                log::warn!("anisette attempt {attempt}/{attempts} failed ({err}), retrying");
                tokio::time::sleep(delay).await;
                attempt += 1;
            }
        }
    }
}

/// The agent identity Apple's GSA edge accepts. Anything naming com.apple.dt.Xcode has been
/// answered with HTTP 503 since Sept 2026, and providers still hand us that string.
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

    fn headers_with(client_info: &str) -> AnisetteData {
        let mut base = HashMap::new();
        base.insert("X-Mme-Client-Info".to_string(), client_info.to_string());
        base.insert("X-Apple-I-MD".to_string(), "otp".to_string());
        AnisetteData::from_headers(base, AnisetteSource::Native)
    }

    // RS-263: a client-info naming com.apple.dt.Xcode gets HTTP 503 from Apple.
    #[test]
    fn rewrites_xcode_agent_to_akd() {
        let out = rewrite_client_info(
            "<iMac21,1> <macOS;27.0;26A428> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",
        );
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

    // The 503 fix has to survive the path login actually takes to build headers.
    #[test]
    fn generated_headers_never_name_xcode_agent() {
        let data = headers_with(
            "<iMac21,1> <macOS;27.0;26A428> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",
        );
        let headers = data.generate_headers(true, true, true);
        let client_info = headers.get("X-Mme-Client-Info").unwrap();
        assert!(client_info.contains("com.apple.akd/1.0"));
        assert!(!client_info.contains("dt.Xcode"));
    }

    #[test]
    fn get_header_returns_rewritten_client_info() {
        let data = headers_with(
            "<iMac21,1> <macOS;27.0;26A428> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>",
        );
        let v = data.get_header("x-mme-client-info").unwrap();
        assert!(v.contains("com.apple.akd/1.0"));
        assert!(!v.contains("dt.xcode"));
    }

    #[test]
    fn source_is_recorded() {
        let data = headers_with("<iMac21,1> <macOS;27.0;26A428> <a (b)>");
        assert_eq!(data.source, AnisetteSource::Native);
    }

    #[test]
    fn default_server_keeps_base_state_dir() {
        let base = PathBuf::from("/x/anisette");
        assert_eq!(remote_state_path(&base, None), base);
    }

    #[test]
    fn custom_server_gets_its_own_state_dir() {
        let base = PathBuf::from("/x/anisette");
        assert_eq!(
            remote_state_path(&base, Some("https://mac-ani.example.com/")),
            base.join("servers/mac-ani.example.com")
        );
        assert_eq!(
            remote_state_path(&base, Some("http://10.0.0.2:6969")),
            base.join("servers/10.0.0.2_6969")
        );
        assert_eq!(remote_state_path(&base, Some("https://..")), base.join("servers/_"));
        assert_ne!(
            remote_state_path(&base, Some("https://a.example/?u=http://x")),
            remote_state_path(&base, Some("https://b.example/?u=http://x"))
        );
    }

    #[test]
    fn config_path_is_under_app_support() {
        let p = anisette_config_path();
        assert!(p.ends_with("Signr/anisette"), "unexpected path {p:?}");
    }

    // RS-276: a decode failure from ani.sidestore.app must be retried, and the
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
}
