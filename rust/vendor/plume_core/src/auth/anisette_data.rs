use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;

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

/// Where the emulated-ADI library and the remote provisioning blob live.
fn anisette_config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home)
        .join("Library/Application Support/Signr")
        .join("anisette")
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
            Ok(Err(e)) => log::warn!("native anisette unavailable ({e}), falling back"),
            Err(_) => log::warn!("native anisette panicked, falling back"),
        }

        let config = AnisetteConfiguration::new()
            .set_configuration_path(anisette_config_path())
            .set_macos_serial(native_anisette::machine_serial().unwrap_or_else(|| "0".to_string()));

        // Tiers 2 and 3: omnisette picks the emulated ADI when the Android library has been
        // provisioned locally, otherwise a remote anisette-v3 server.
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
        if !self.is_valid() {
            panic!("Invalid data!")
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
    fn config_path_is_under_app_support() {
        let p = anisette_config_path();
        assert!(p.ends_with("Signr/anisette"), "unexpected path {p:?}");
    }
}
